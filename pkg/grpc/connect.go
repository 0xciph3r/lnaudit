package grpc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// rpcTimeout is the maximum time allowed for a single gRPC call.
const rpcTimeout = 10 * time.Second

// maxStringLen caps the length of untrusted strings from gRPC responses,
// measured in runes (Unicode code points) after sanitization.
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
	home, _ := os.UserHomeDir()

	// redact replaces the home directory prefix in path with $HOME, but only
	// when the boundary falls on a path separator (or is an exact match).
	// This prevents /home/al from matching /home/alice2/secret.
	redact := func(path string) string {
		if home == "" {
			return path
		}
		cleanPath := filepath.Clean(path)
		cleanHome := filepath.Clean(home)
		if cleanPath == cleanHome {
			return "$HOME"
		}
		prefix := cleanHome + string(filepath.Separator)
		if strings.HasPrefix(cleanPath, prefix) {
			return "$HOME" + cleanPath[len(cleanHome):]
		}
		return path
	}

	// Load TLS certificate
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert %s: %w", redact(tlsCertPath), err)
	}

	// Load macaroon
	macBytes, err := os.ReadFile(macaroonPath)
	if err != nil {
		return nil, fmt.Errorf("reading macaroon %s: %w", redact(macaroonPath), err)
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

// truncate strips ANSI/VT escape sequences and non-printable control
// characters from s, then caps the result to maxStringLen runes.
// Rune-based slicing avoids splitting multi-byte UTF-8 sequences.
// The sanitization and length check share a single []rune conversion.
func truncate(s string) string {
	out := sanitizeRunes([]rune(s))
	if len(out) > maxStringLen {
		return string(out[:maxStringLen]) + "...(truncated)"
	}
	return string(out)
}

// sanitizeRunes removes ANSI/VT escape sequences and non-printable control
// characters from runes, returning only safe printable content.
//
// Sequences handled:
//   - CSI (ESC [): skip until final byte in range 0x40-0x7E
//   - OSC (ESC ]): skip until BEL (\x07), 8-bit ST (\x9C), or ESC-backslash (2-byte ST)
//   - Other ESC sequences: skip ESC plus the following character
func sanitizeRunes(runes []rune) []rune {
	out := make([]rune, 0, len(runes))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\x1b' && i+1 < len(runes) {
			i++
			next := runes[i]
			switch next {
			case '[':
				// CSI sequence: skip until final byte (0x40-0x7E inclusive)
				for i+1 < len(runes) {
					i++
					if runes[i] >= 0x40 && runes[i] <= 0x7e {
						break
					}
				}
			case ']':
				// OSC sequence: skip until BEL, 8-bit ST, or ESC-backslash (2-byte ST)
				for i+1 < len(runes) {
					i++
					if runes[i] == '\x07' || runes[i] == '\x9c' {
						break
					}
					if runes[i] == '\x1b' && i+1 < len(runes) && runes[i+1] == '\\' {
						i++ // consume the backslash
						break
					}
				}
			default:
				// Other ESC sequences: ESC + one char already consumed; skip both.
			}
			continue
		}
		// Allow printable runes and safe whitespace only.
		if unicode.IsPrint(r) || r == ' ' || r == '\t' || r == '\n' {
			out = append(out, r)
		}
	}
	return out
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
		c := Channel{
			ChanID:          ch.ChanId,
			RemotePubkey:    truncate(ch.RemotePubkey),
			Capacity:        ch.Capacity,
			LocalBalance:    ch.LocalBalance,
			RemoteBalance:   ch.RemoteBalance,
			Active:          ch.Active,
			Private:         ch.Private,
			NumPendingHTLCs: len(ch.PendingHtlcs),
			ZeroConf:        ch.ZeroConf,
			PushAmountSat:   int64(ch.PushAmountSat),
			CommitmentType:  ch.CommitmentType.String(),
		}
		if ch.RemoteConstraints != nil {
			c.RemoteMaxHTLCs = ch.RemoteConstraints.MaxAcceptedHtlcs
		}
		channels[i] = c
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
