package cmd

import (
	"fmt"
	"os"
	"time"

	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
	"github.com/0xciph3r/lnaudit/pkg/jamming"
	"github.com/0xciph3r/lnaudit/pkg/lndpath"
	"github.com/0xciph3r/lnaudit/pkg/report"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	jammingFromFile           string
	jammingLndDir             string
	jammingConnectAddr        string
	jammingMacaroonPath       string
	jammingTLSCertPath        string
	jammingRecordPath         string
	jammingOutputFormat       string
	jammingMinSeverity        string
	jammingFailOn             string
	jammingNoColor            bool
	jammingQuiet              bool
	jammingEmitObserved       bool
	jammingSlotThreshold      float64
	jammingLiquidityThreshold float64
	jammingMinSustained       int
)

var jammingCmd = &cobra.Command{
	Use:   "jamming",
	Short: "Channel-jamming analysis tools",
}

var jammingAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze channel-jamming pressure from timeline replay or live snapshot",
	Long: `Analyze channel-jamming pressure signals from an offline timeline JSON file
or a live LND snapshot.

This command is independent from "scan" and does not change scan behavior.`,
	RunE: runJammingAnalyze,
}

func init() {
	jammingAnalyzeCmd.Flags().StringVar(&jammingFromFile, "from-file", "", "path to timeline JSON fixture")
	jammingAnalyzeCmd.Flags().StringVar(&jammingLndDir, "lnddir", "", "LND data directory for auto-detected credentials")
	jammingAnalyzeCmd.Flags().StringVar(&jammingConnectAddr, "connect", "", "gRPC address of running LND node (e.g., localhost:10009)")
	jammingAnalyzeCmd.Flags().StringVar(&jammingMacaroonPath, "macaroon", "", "path to macaroon for --connect mode")
	jammingAnalyzeCmd.Flags().StringVar(&jammingTLSCertPath, "tlscert", "", "path to tls.cert for --connect mode")
	jammingAnalyzeCmd.Flags().StringVar(&jammingRecordPath, "record", "", "append live snapshot to timeline file")
	jammingAnalyzeCmd.Flags().StringVar(&jammingOutputFormat, "format", "table", "output format: table, json, sarif")
	jammingAnalyzeCmd.Flags().StringVar(&jammingMinSeverity, "min-severity", "low", "minimum severity to display: critical, high, medium, low, info")
	jammingAnalyzeCmd.Flags().StringVar(&jammingFailOn, "fail-on", "critical", "exit 1 if any finding at or above this severity")
	jammingAnalyzeCmd.Flags().BoolVar(&jammingNoColor, "no-color", false, "disable colored output")
	jammingAnalyzeCmd.Flags().BoolVar(&jammingQuiet, "quiet", false, "only output the score")
	jammingAnalyzeCmd.Flags().BoolVar(&jammingEmitObserved, "emit-observed", false, "include non-sustained observed spikes in output")
	jammingAnalyzeCmd.Flags().Float64Var(&jammingSlotThreshold, "slot-threshold", 0.60, "slot saturation threshold ratio (0-1]")
	jammingAnalyzeCmd.Flags().Float64Var(&jammingLiquidityThreshold, "liquidity-threshold", 0.60, "liquidity saturation threshold ratio (0-1]")
	jammingAnalyzeCmd.Flags().IntVar(&jammingMinSustained, "min-sustained-samples", 3, "minimum consecutive samples for sustained findings (>=2)")

	jammingCmd.AddCommand(jammingAnalyzeCmd)
	rootCmd.AddCommand(jammingCmd)
}

func runJammingAnalyze(cmd *cobra.Command, args []string) error {
	if err := validateJammingAnalyzeFlags(); err != nil {
		return err
	}

	timeline, err := resolveJammingTimeline()
	if err != nil {
		return err
	}

	findings := jamming.Analyze(timeline, jamming.Options{
		SlotSaturationThreshold:      jammingSlotThreshold,
		LiquiditySaturationThreshold: jammingLiquidityThreshold,
		MinSustainedSamples:          jammingMinSustained,
		EmitObserved:                 jammingEmitObserved,
	})

	fullScore := report.JammingScore(findings)
	fullRating := report.JammingRating(findings)
	fullSummary := report.JammingSummary(findings)
	fullSummaryStrings := report.JammingSummaryStrings(findings)

	failThreshold, _ := scanner.ParseSeverity(jammingFailOn)
	minThreshold, _ := scanner.ParseSeverity(jammingMinSeverity)
	filtered := filterJammingFindings(findings, minThreshold)
	hasFailure := hasJammingFindingsAtOrAbove(findings, failThreshold)
	if len(timeline.Snapshots) < jammingMinSustained && !jammingEmitObserved && !jammingQuiet {
		fmt.Fprintf(
			os.Stderr,
			"  ⚠  collected %d snapshot(s); sustained findings require at least %d samples. Use --record or --emit-observed for single-snapshot visibility.\n",
			len(timeline.Snapshots),
			jammingMinSustained,
		)
	}

	if jammingQuiet {
		fmt.Printf("%d\n", fullScore)
	} else {
		switch jammingOutputFormat {
		case "json":
			if err := report.JammingJSONWriterWithScore(os.Stdout, filtered, fullScore, fullRating, fullSummaryStrings); err != nil {
				return fmt.Errorf("writing jamming JSON: %w", err)
			}
		case "sarif":
			if err := report.JammingSARIFWriterWithScore(os.Stdout, filtered, fullScore, fullRating, fullSummaryStrings); err != nil {
				return fmt.Errorf("writing jamming SARIF: %w", err)
			}
		default:
			report.JammingTableWriterWithScore(os.Stdout, filtered, fullScore, fullRating, fullSummary, !jammingNoColor)
		}
	}

	if hasFailure {
		os.Exit(1)
	}
	return nil
}

func validateJammingAnalyzeFlags() error {
	allowedFormats := map[string]struct{}{
		"table": {},
		"json":  {},
		"sarif": {},
	}
	if err := validateOutputFlagValues(
		jammingOutputFormat,
		allowedFormats,
		"table, json, sarif",
		jammingFailOn,
		jammingMinSeverity,
	); err != nil {
		return err
	}

	if jammingFromFile == "" && jammingConnectAddr == "" {
		return fmt.Errorf("one of --from-file or --connect must be set")
	}
	if jammingFromFile != "" && jammingConnectAddr != "" {
		return fmt.Errorf("--from-file and --connect cannot be used together")
	}
	if jammingRecordPath != "" && jammingConnectAddr == "" {
		return fmt.Errorf("--record requires --connect")
	}
	if jammingSlotThreshold <= 0 || jammingSlotThreshold > 1 {
		return fmt.Errorf("invalid --slot-threshold %.4f: expected value in (0,1]", jammingSlotThreshold)
	}
	if jammingLiquidityThreshold <= 0 || jammingLiquidityThreshold > 1 {
		return fmt.Errorf("invalid --liquidity-threshold %.4f: expected value in (0,1]", jammingLiquidityThreshold)
	}
	if jammingMinSustained < 2 {
		return fmt.Errorf("invalid --min-sustained-samples %d: must be >= 2", jammingMinSustained)
	}
	return nil
}

func resolveJammingTimeline() (jamming.Timeline, error) {
	if jammingFromFile != "" {
		timeline, err := jamming.LoadTimeline(jammingFromFile)
		if err != nil {
			return jamming.Timeline{}, err
		}
		if len(timeline.Snapshots) == 0 {
			return jamming.Timeline{}, fmt.Errorf("timeline %s has no snapshots", jammingFromFile)
		}
		return timeline, nil
	}

	certPath := jammingTLSCertPath
	macPath := jammingMacaroonPath
	if certPath == "" || macPath == "" {
		paths, err := lndpath.Detect(jammingLndDir, "")
		if err != nil {
			return jamming.Timeline{}, fmt.Errorf("detecting LND paths: %w", err)
		}
		if certPath == "" {
			certPath = paths.TLSCert
		}
		if macPath == "" {
			macPath = paths.AdminMacaroon()
		}
	}
	if certPath == "" {
		return jamming.Timeline{}, fmt.Errorf("no TLS cert found; set --tlscert or --lnddir")
	}
	if macPath == "" {
		return jamming.Timeline{}, fmt.Errorf("no macaroon found; set --macaroon or --lnddir")
	}

	client, err := lngrpc.Connect(jammingConnectAddr, certPath, macPath)
	if err != nil {
		return jamming.Timeline{}, fmt.Errorf("connecting to LND for jamming analysis: %w", err)
	}
	defer client.Close()

	snapshot, err := jamming.RecordSnapshot(client, time.Now().UTC())
	if err != nil {
		return jamming.Timeline{}, err
	}

	if jammingRecordPath != "" {
		if err := jamming.AppendSnapshot(jammingRecordPath, snapshot); err != nil {
			return jamming.Timeline{}, err
		}
		timeline, err := jamming.LoadTimeline(jammingRecordPath)
		if err != nil {
			return jamming.Timeline{}, err
		}
		if len(timeline.Snapshots) == 0 {
			return jamming.Timeline{}, fmt.Errorf("timeline %s has no snapshots", jammingRecordPath)
		}
		return timeline, nil
	}

	return jamming.Timeline{Snapshots: []jamming.Snapshot{snapshot}}, nil
}

func filterJammingFindings(findings []jamming.Finding, minSeverity scanner.Severity) []jamming.Finding {
	filtered := make([]jamming.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity >= minSeverity {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func hasJammingFindingsAtOrAbove(findings []jamming.Finding, threshold scanner.Severity) bool {
	for _, finding := range findings {
		if finding.Severity >= threshold {
			return true
		}
	}
	return false
}
