package cmd

import (
	"fmt"
	"os"

	"github.com/0xciph3r/lnaudit/pkg/checks"
	"github.com/0xciph3r/lnaudit/pkg/config"
	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
	"github.com/0xciph3r/lnaudit/pkg/lndpath"
	"github.com/0xciph3r/lnaudit/pkg/report"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	configPath   string
	lndDir       string
	outputFormat string
	minSeverity  string
	failOn       string
	connectAddr  string
	macaroonPath string
	tlsCertPath  string
	verbose      bool
	noColor      bool
	quiet        bool
)

type scanOptions struct {
	configPath   string
	lndDir       string
	connectAddr  string
	macaroonPath string
	tlsCertPath  string
}

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
	scanCmd.Flags().StringVar(&connectAddr, "connect", "", "gRPC address of running LND node (e.g., localhost:10009)")
	scanCmd.Flags().StringVar(&macaroonPath, "macaroon", "", "path to admin.macaroon (auto-detected if --connect is set)")
	scanCmd.Flags().StringVar(&tlsCertPath, "tlscert", "", "path to tls.cert for gRPC (auto-detected from lnddir)")
	scanCmd.Flags().BoolVar(&verbose, "verbose", false, "show INFO-level findings")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
	scanCmd.Flags().BoolVar(&quiet, "quiet", false, "only output the score")

	rootCmd.AddCommand(scanCmd)
}

// isInteractive returns true when we should show the Bubble Tea UI.
func isInteractive() bool {
	if quiet || outputFormat == "json" || noColor {
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// executeScanWithOptions runs all scan checks with optional progress reporting.
func executeScanWithOptions(opts scanOptions, progress func(string)) (*scanner.Report, []string, error) {
	var warnings []string

	// 1. Detect paths
	progress("Detecting LND paths")
	paths, err := lndpath.Detect(opts.lndDir, opts.configPath)
	if err != nil && opts.connectAddr == "" {
		return nil, nil, fmt.Errorf("detecting LND paths: %w", err)
	}

	// 2. Parse config
	var cfg *config.LndConfig
	if paths.ConfigFile != "" {
		progress("Parsing configuration")
		cfg, err = config.Parse(paths.ConfigFile)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing config: %w", err)
		}
		if cfg.Bitcoin.Network != "" {
			paths.Network = cfg.Bitcoin.Network
		}
	} else if opts.connectAddr == "" {
		return nil, nil, fmt.Errorf("no lnd.conf found (searched %s). Use --config to specify the path", paths.LndDir)
	}

	// 3. Run checks
	r := &scanner.Report{}

	if cfg != nil {
		progress("Checking file permissions")
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

		progress("Auditing transport security")
		for _, f := range checks.CheckTLSCert(paths.TLSCert) {
			r.Add(f)
		}
		for _, f := range checks.CheckRPCBindAddress(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckExternalIPLeak(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckTLSHardening(cfg) {
			r.Add(f)
		}

		progress("Checking access controls")
		for _, f := range checks.CheckNoMacaroons(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckAdminMacaroonLeaks(paths.DataDir) {
			r.Add(f)
		}
		for _, f := range checks.CheckMacaroonLeastPrivilege(paths.LndDir, paths.DataDir) {
			r.Add(f)
		}
		for _, f := range checks.CheckSecretHygieneLeaks(paths.LndDir, paths.DataDir) {
			r.Add(f)
		}
		for _, f := range checks.CheckDangerousFlags(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckDangerousFlagsExtended(cfg) {
			r.Add(f)
		}

		progress("Scanning network privacy")
		for _, f := range checks.CheckTorConfig(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckPrivacySettings(cfg) {
			r.Add(f)
		}

		progress("Auditing channel safety")
		for _, f := range checks.CheckChannelSafety(cfg) {
			r.Add(f)
		}

		progress("Checking network exposure")
		for _, f := range checks.CheckNetworkExposure(cfg) {
			r.Add(f)
		}

		progress("Auditing channel policy")
		for _, f := range checks.CheckChannelPolicy(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckBitcoinPolicy(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckPaymentSecurity(cfg) {
			r.Add(f)
		}

		progress("Checking protocol security")
		for _, f := range checks.CheckProtocolSecurity(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckAutopilotSecurity(cfg) {
			r.Add(f)
		}
		for _, f := range checks.CheckGossipSecurity(cfg) {
			r.Add(f)
		}
	}

	progress("Scanning open ports")
	portHost := "localhost"
	if opts.connectAddr != "" {
		portHost = opts.connectAddr
	}
	for _, f := range checks.CheckOpenPorts(portHost) {
		r.Add(f)
	}

	// 4. Live checks
	if opts.connectAddr != "" {
		progress("Connecting to LND node")

		certPath := opts.tlsCertPath
		if certPath == "" {
			certPath = paths.TLSCert
		}
		macPath := opts.macaroonPath
		if macPath == "" {
			macPath = paths.AdminMacaroon()
		}

		client, err := lngrpc.Connect(opts.connectAddr, certPath, macPath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Live scan error: %v — config-only results shown", err))
		} else {
			defer client.Close()

			liveChecks := []struct {
				name  string
				label string
				fn    func(lngrpc.LndClient) ([]scanner.Finding, error)
			}{
				{"version/CVE", "Checking LND version and CVEs", checks.CheckLndVersion},
				{"chain sync", "Verifying chain sync", checks.CheckChainSync},
				{"peer count", "Checking peer connectivity", checks.CheckPeerCount},
				{"force-close", "Scanning force-close risks", checks.CheckPendingForceClose},
				{"balance", "Auditing balance exposure", checks.CheckLargeLocalBalance},
				{"jamming", "Checking for channel jamming", checks.CheckChannelJamming},
				{"zero-conf", "Detecting zero-conf channels", checks.CheckZeroConfChannels},
				{"htlc-limits", "Auditing HTLC limits", checks.CheckHighHTLCLimits},
			}

			for _, lc := range liveChecks {
				progress(lc.label)
				results, err := lc.fn(client)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s check failed: %v", lc.name, err))
					continue
				}
				for _, f := range results {
					r.Add(f)
				}
			}
		}
	}

	return r, warnings, nil
}

// executeScan runs all scan checks with optional progress reporting.
func executeScan(progress func(string)) (*scanner.Report, []string, error) {
	return executeScanWithOptions(scanOptions{
		configPath:   configPath,
		lndDir:       lndDir,
		connectAddr:  connectAddr,
		macaroonPath: macaroonPath,
		tlsCertPath:  tlsCertPath,
	}, progress)
}

func runScan(cmd *cobra.Command, args []string) error {
	if isInteractive() {
		return runInteractiveScan()
	}
	return runNonInteractiveScan()
}

func runInteractiveScan() error {
	model := newScanModel(func(p *tea.Program) scanResult {
		progress := func(phase string) { sendPhase(p, phase) }

		r, w, err := executeScan(progress)
		return scanResult{report: r, warnings: w, err: err}
	})

	p := tea.NewProgram(model, tea.WithOutput(os.Stderr))
	model.programRef = p

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("UI error: %w", err)
	}

	m := finalModel.(scanModel)
	if m.result == nil {
		return fmt.Errorf("scan interrupted")
	}
	if m.result.err != nil {
		return m.result.err
	}

	// Print any warnings collected during the scan
	for _, w := range m.result.warnings {
		fmt.Fprintf(os.Stderr, "  ⚠  %s\n", w)
	}

	return renderReport(m.result.report)
}

func runNonInteractiveScan() error {
	progress := func(phase string) {
		if !quiet {
			fmt.Fprintf(os.Stderr, "  → %s...\n", phase)
		}
	}

	r, warnings, err := executeScan(progress)
	if err != nil {
		return err
	}

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  ⚠  %s\n", w)
	}

	return renderReport(r)
}

func renderReport(r *scanner.Report) error {
	fullScore := r.Score()
	fullRating := r.Rating()
	fullSummary := r.Summary()
	hasFailure := false
	if threshold, err := scanner.ParseSeverity(failOn); err == nil {
		hasFailure = r.HasFindingsAtOrAbove(threshold)
	}

	// Filter for display
	var display *scanner.Report
	if !verbose {
		display = filterReport(r, scanner.Low)
	} else {
		display = filterReport(r, scanner.Info)
	}

	if sev, err := scanner.ParseSeverity(minSeverity); err == nil && sev > scanner.Info {
		display = filterReport(display, sev)
	}

	// Output
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
