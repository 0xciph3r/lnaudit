package grpc

// NodeInfo contains version and sync status from LND's GetInfo RPC.
type NodeInfo struct {
	Version            string
	CommitHash         string
	SyncedToChain      bool
	SyncedToGraph      bool
	NumPeers           int
	NumActiveChannels  int
	NumPendingChannels int
	BlockHeight        uint32
}

// Channel represents a single active Lightning channel.
type Channel struct {
	ChanID        uint64
	RemotePubkey  string
	Capacity      int64
	LocalBalance  int64
	RemoteBalance int64
	Active        bool
	Private       bool
}

// PendingForceClose represents a channel being force-closed.
type PendingForceClose struct {
	ChannelPoint     string
	ClosingTxHash    string
	LimboBalance     int64
	RecoveredBalance int64
}

// WalletBalance contains on-chain wallet balances in satoshis.
type WalletBalance struct {
	TotalBalance       int64
	ConfirmedBalance   int64
	UnconfirmedBalance int64
}

// LndClient defines the interface for querying an LND node's runtime state.
// Implementations include the real gRPC client and a mock for testing.
type LndClient interface {
	GetInfo() (*NodeInfo, error)
	ListChannels() ([]Channel, error)
	PendingChannels() ([]PendingForceClose, error)
	WalletBalance() (*WalletBalance, error)
	Close() error
}
