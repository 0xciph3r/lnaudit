package grpc

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// rpcTimeout is the maximum time allowed for a single gRPC call.
const rpcTimeout = 10 * time.Second

// maxStringLen caps the length of untrusted strings from gRPC responses.
const maxStringLen = 4096

// realClient wraps an actual gRPC connection to LND.
type realClient struct {
	conn   *grpc.ClientConn
	client lnrpc.LightningClient
}

// Connect establishes a gRPC connection to a running LND node.
// It loads TLS credentials from tlsCertPath and authenticates
// with the macaroon at macaroonPath.
func Connect(host, tlsCertPath, macaroonPath string) (LndClient, error) {
	// Load TLS certificate
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert %s: %w", tlsCertPath, err)
	}

	// Load macaroon
	macBytes, err := os.ReadFile(macaroonPath)
	if err != nil {
		return nil, fmt.Errorf("reading macaroon %s: %w", macaroonPath, err)
	}

	// Zero out raw bytes after parsing
	defer func() {
		for i := range macBytes {
			macBytes[i] = 0
		}
	}()

	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("decoding macaroon: %w", err)
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("creating macaroon credential: %w", err)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(macCred),
	}

	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("connecting to LND at %s: %w", host, err)
	}

	return &realClient{
		conn:   conn,
		client: lnrpc.NewLightningClient(conn),
	}, nil
}

// truncate caps a string at maxStringLen to prevent memory abuse
// from malicious gRPC responses.
func truncate(s string) string {
	if len(s) > maxStringLen {
		return s[:maxStringLen] + "...(truncated)"
	}
	return s
}

func (c *realClient) GetInfo() (*NodeInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetInfo: %w", err)
	}

	return &NodeInfo{
		Version:            truncate(resp.Version),
		CommitHash:         truncate(resp.CommitHash),
		SyncedToChain:      resp.SyncedToChain,
		SyncedToGraph:      resp.SyncedToGraph,
		NumPeers:           int(resp.NumPeers),
		NumActiveChannels:  int(resp.NumActiveChannels),
		NumPendingChannels: int(resp.NumPendingChannels),
		BlockHeight:        resp.BlockHeight,
	}, nil
}

func (c *realClient) ListChannels() ([]Channel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.ListChannels(ctx, &lnrpc.ListChannelsRequest{})
	if err != nil {
		return nil, fmt.Errorf("ListChannels: %w", err)
	}

	channels := make([]Channel, len(resp.Channels))
	for i, ch := range resp.Channels {
		channels[i] = Channel{
			ChanID:        ch.ChanId,
			RemotePubkey:  truncate(ch.RemotePubkey),
			Capacity:      ch.Capacity,
			LocalBalance:  ch.LocalBalance,
			RemoteBalance: ch.RemoteBalance,
			Active:        ch.Active,
			Private:       ch.Private,
		}
	}

	return channels, nil
}

func (c *realClient) PendingChannels() ([]PendingForceClose, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.PendingChannels(ctx, &lnrpc.PendingChannelsRequest{})
	if err != nil {
		return nil, fmt.Errorf("PendingChannels: %w", err)
	}

	pending := make([]PendingForceClose, 0, len(resp.PendingForceClosingChannels))
	for _, fc := range resp.PendingForceClosingChannels {
		pending = append(pending, PendingForceClose{
			ChannelPoint:     truncate(fc.Channel.ChannelPoint),
			ClosingTxHash:    truncate(fc.ClosingTxid),
			LimboBalance:     fc.LimboBalance,
			RecoveredBalance: fc.RecoveredBalance,
		})
	}

	return pending, nil
}

func (c *realClient) WalletBalance() (*WalletBalance, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()

	resp, err := c.client.WalletBalance(ctx, &lnrpc.WalletBalanceRequest{})
	if err != nil {
		return nil, fmt.Errorf("WalletBalance: %w", err)
	}

	return &WalletBalance{
		TotalBalance:       resp.TotalBalance,
		ConfirmedBalance:   resp.ConfirmedBalance,
		UnconfirmedBalance: resp.UnconfirmedBalance,
	}, nil
}

func (c *realClient) Close() error {
	return c.conn.Close()
}
