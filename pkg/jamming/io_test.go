package jamming

import (
	"path/filepath"
	"testing"
	"time"

	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
)

func TestSnapshotFromChannels_MapsPendingValue(t *testing.T) {
	snapshot := SnapshotFromChannels(time.Unix(1, 0).UTC(), []lngrpc.Channel{
		{
			ChanID:              42,
			RemotePubkey:        "abc",
			Capacity:            1_000_000,
			LocalBalance:        400_000,
			RemoteBalance:       600_000,
			NumPendingHTLCs:     3,
			PendingHTLCValueSat: 12_000,
			RemoteMaxHTLCs:      30,
		},
	})

	if len(snapshot.Channels) != 1 {
		t.Fatalf("channels = %d, want 1", len(snapshot.Channels))
	}
	if snapshot.Channels[0].PendingHTLCValueSat != 12_000 {
		t.Fatalf("pending value = %d, want 12000", snapshot.Channels[0].PendingHTLCValueSat)
	}
}

func TestAppendSnapshot_CreatesTimelineFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timeline.json")
	snapshot := Snapshot{
		Timestamp: time.Unix(100, 0).UTC(),
		Channels:  []ChannelSample{{ChanID: 1, CapacitySat: 10}},
	}

	if err := AppendSnapshot(path, snapshot); err != nil {
		t.Fatalf("AppendSnapshot error: %v", err)
	}

	loaded, err := LoadTimeline(path)
	if err != nil {
		t.Fatalf("LoadTimeline error: %v", err)
	}
	if len(loaded.Snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(loaded.Snapshots))
	}
}
