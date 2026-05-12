package grpc

// MockClient is a test double for LndClient.
// Set fields to control return values in tests.
type MockClient struct {
	NodeInfoResp *NodeInfo
	NodeInfoErr  error
	ChannelsResp []Channel
	ChannelsErr  error
	PendingResp  []PendingForceClose
	PendingErr   error
	WalletResp   *WalletBalance
	WalletErr    error
}

func (m *MockClient) GetInfo() (*NodeInfo, error) {
	return m.NodeInfoResp, m.NodeInfoErr
}

func (m *MockClient) ListChannels() ([]Channel, error) {
	return m.ChannelsResp, m.ChannelsErr
}

func (m *MockClient) PendingChannels() ([]PendingForceClose, error) {
	return m.PendingResp, m.PendingErr
}

func (m *MockClient) WalletBalance() (*WalletBalance, error) {
	return m.WalletResp, m.WalletErr
}

func (m *MockClient) Close() error {
	return nil
}
