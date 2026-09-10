package jamming

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
)

// SnapshotFromChannels maps a live channel list into a jamming analysis snapshot.
func SnapshotFromChannels(ts time.Time, channels []lngrpc.Channel) Snapshot {
	samples := make([]ChannelSample, 0, len(channels))
	for _, ch := range channels {
		samples = append(samples, ChannelSample{
			ChanID:              ch.ChanID,
			RemotePubkey:        ch.RemotePubkey,
			CapacitySat:         ch.Capacity,
			LocalBalanceSat:     ch.LocalBalance,
			RemoteBalanceSat:    ch.RemoteBalance,
			PendingHTLCCount:    ch.NumPendingHTLCs,
			PendingHTLCValueSat: ch.PendingHTLCValueSat,
			RemoteMaxHTLCs:      ch.RemoteMaxHTLCs,
		})
	}
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].ChanID < samples[j].ChanID
	})
	return Snapshot{
		Timestamp: ts.UTC(),
		Channels:  samples,
	}
}

// RecordSnapshot fetches channels from a live LND client and converts them to a snapshot.
func RecordSnapshot(client lngrpc.LndClient, now time.Time) (Snapshot, error) {
	channels, err := client.ListChannels()
	if err != nil {
		return Snapshot{}, fmt.Errorf("record snapshot: %w", err)
	}
	return SnapshotFromChannels(now, channels), nil
}

// LoadTimeline reads a timeline JSON file from disk.
func LoadTimeline(path string) (Timeline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Timeline{}, fmt.Errorf("read timeline %s: %w", path, err)
	}
	var timeline Timeline
	if err := json.Unmarshal(raw, &timeline); err != nil {
		return Timeline{}, fmt.Errorf("decode timeline %s: %w", path, err)
	}
	return timeline, nil
}

// SaveTimeline writes a timeline JSON file to disk with secure permissions.
func SaveTimeline(path string, timeline Timeline) error {
	raw, err := json.MarshalIndent(timeline, "", "  ")
	if err != nil {
		return fmt.Errorf("encode timeline: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write timeline %s: %w", path, err)
	}
	return nil
}

// AppendSnapshot appends a snapshot to a timeline file, creating the file when missing.
func AppendSnapshot(path string, snapshot Snapshot) error {
	timeline := Timeline{}
	if _, err := os.Stat(path); err == nil {
		loaded, loadErr := LoadTimeline(path)
		if loadErr != nil {
			return loadErr
		}
		timeline = loaded
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat timeline %s: %w", path, err)
	}

	timeline.Snapshots = append(timeline.Snapshots, snapshot)
	return SaveTimeline(path, timeline)
}
