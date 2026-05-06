package cmd

import (
	"fmt"
	"os"

	"github.com/NonsoAmadi10/lnaudit/pkg/checks"
	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/lndpath"
	"github.com/NonsoAmadi10/lnaudit/pkg/report"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	configPath   string
	lndDir       string
	outputFormat string
	minSeverity  string
	failOn       string
	verbose      bool
	noColor      bool
	quiet        bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan an LND node for security issues",
	Long: `Scan an LND node's configuration and runtime state for security
misconfigurations, weak defaults, and hardening opportunities.

Supports two modes:
  - Config-only: reads lnd.conf and the data directory (no running node needed)
  - Live: connects via gRPC for runtime checks (requires a running node)

If no --config flag is provided, the scanner will attempt to auto-detect
the LND configuration at common paths (~/.lnd/lnd.conf).`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&configPath, "config", "", "path to lnd.conf (auto-detected if not set)")
	scanCmd.Flags().StringVar(&lndDir, "lnddir", "", "LND data directory (auto-detected if not set)")
	scanCmd.Flags().StringVar(&outputFormat, "format", "table", "output format: table, json")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "low", "minimum severity to display: critical, high, medium, low, info")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "critical", "exit 1 if any finding at or above this severity")
	scanCmd.Flags().BoolVar(&verbose, "verbose", false, "show INFO-level findings")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
	scanCmd.Flags().BoolVar(&quiet, "quiet", false, "only output the score")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// 1. Detect paths
	paths, err := lndpath.Detect(lndDir, configPath)
	if err != nil {
		return fmt.Errorf("detecting LND paths: %w", err)
	}

	if paths.ConfigFile == "" {
		fmt.Fprintln(os.Stderr, "⚠  No lnd.conf found. Use --config to specify the path.")
		fmt.Fprintln(os.Stderr, "   Searched:", paths.LndDir)
		return fmt.Errorf("no configuration file found")
	}

	// 2. Parse config
	cfg, err := config.Parse(paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	// Update paths with network from config if available
	if cfg.Bitcoin.Network != "" {
		paths.Network = cfg.Bitcoin.Network
	}

	// 3. Run all checks
	r := &scanner.Report{}

	// File permission checks
	filePaths := checks.FilePaths{
		WalletDB:         paths.WalletDB(),
		TLSKey:           paths.TLSKey,
		AdminMacaroon:    paths.AdminMacaroon(),
		ReadonlyMacaroon: paths.ReadonlyMacaroon(),
		InvoiceMacaroon:  paths.InvoiceMacaroon(),
		ChannelBackup:    paths.ChannelBackup(),
		ConfigFile:       paths.ConfigFile,
	}
	for _, f := range checks.CheckFilePermissions(filePaths) {
		r.Add(f)
	}

	// Transport checks
	for _, f := range checks.CheckTLSCert(paths.TLSCert) {
		r.Add(f)
	}
	for _, f := range checks.CheckRPCBindAddress(cfg) {
		r.Add(f)
	}
	for _, f := range checks.CheckExternalIPLeak(cfg) {
		r.Add(f)
	}

	// Access control checks
	for _, f := range checks.CheckNoMacaroons(cfg) {
		r.Add(f)
	}
	for _, f := range checks.CheckAdminMacaroonLeaks(paths.DataDir) {
		r.Add(f)
	}

	// Dangerous flags
	for _, f := range checks.CheckDangerousFlags(cfg) {
		r.Add(f)
	}

	// Network privacy checks
	for _, f := range checks.CheckTorConfig(cfg) {
		r.Add(f)
	}
	for _, f := range checks.CheckPrivacySettings(cfg) {
		r.Add(f)
	}

	// Channel safety checks
	for _, f := range checks.CheckChannelSafety(cfg) {
		r.Add(f)
	}

	// 4. Compute score on the FULL unfiltered report (always reflects true posture)
	fullScore := r.Score()
	fullRating := r.Rating()
	fullSummary := r.Summary()
	hasFailure := false
	if threshold, err := scanner.ParseSeverity(failOn); err == nil {
		hasFailure = r.HasFindingsAtOrAbove(threshold)
	}

	// 5. Filter for display only (does NOT affect score)
	var display *scanner.Report
	if !verbose {
		display = filterReport(r, scanner.Low)
	} else {
		display = filterReport(r, scanner.Info)
	}

	if sev, err := scanner.ParseSeverity(minSeverity); err == nil && sev > scanner.Info {
		display = filterReport(display, sev)
	}

	// 6. Output (use filtered findings but full score)
	if quiet {
		fmt.Printf("%d\n", fullScore)
	} else {
		switch outputFormat {
		case "json":
			if err := report.JSONWriterWithScore(os.Stdout, display, fullScore, fullRating, fullSummary); err != nil {
				return fmt.Errorf("writing JSON: %w", err)
			}
		default:
			report.TableWriterWithScore(os.Stdout, display, fullScore, fullRating, fullSummary, !noColor)
		}
	}

	// 7. Exit code for CI/CD (based on FULL report, not filtered)
	if hasFailure {
		os.Exit(1)
	}

	return nil
}

func filterReport(r *scanner.Report, minSev scanner.Severity) *scanner.Report {
	filtered := &scanner.Report{}
	for _, f := range r.Findings {
		if f.Severity >= minSev {
			filtered.Add(f)
		}
	}
	return filtered
}
