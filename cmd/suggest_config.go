package cmd

import (
	"fmt"
	"os"

	"github.com/0xciph3r/lnaudit/pkg/confgen"
	"github.com/spf13/cobra"
)

var (
	suggestConfigPath   string
	suggestLndDir       string
	suggestConnectAddr  string
	suggestMacaroonPath string
	suggestTLSCertPath  string
	suggestOutput       string
	suggestForce        bool
)

var suggestConfigCmd = &cobra.Command{
	Use:   "suggest-config",
	Short: "Suggest lnd.conf changes from scan findings",
	Long: `Run lnaudit checks and produce a findings-aware config patch suggestion.

The command does not modify your existing lnd.conf. It outputs a patch-style
set of recommended key=value entries plus manual actions that cannot be
expressed directly in config keys.`,
	RunE: runSuggestConfig,
}

func init() {
	suggestConfigCmd.Flags().StringVar(&suggestConfigPath, "config", "", "path to lnd.conf (auto-detected if not set)")
	suggestConfigCmd.Flags().StringVar(&suggestLndDir, "lnddir", "", "LND data directory (auto-detected if not set)")
	suggestConfigCmd.Flags().StringVar(&suggestConnectAddr, "connect", "", "gRPC address of running LND node (optional)")
	suggestConfigCmd.Flags().StringVar(&suggestMacaroonPath, "macaroon", "", "path to macaroon for --connect mode")
	suggestConfigCmd.Flags().StringVar(&suggestTLSCertPath, "tlscert", "", "path to tls.cert for --connect mode")
	suggestConfigCmd.Flags().StringVarP(&suggestOutput, "output", "o", "", "write suggestion output to file instead of stdout")
	suggestConfigCmd.Flags().BoolVar(&suggestForce, "force", false, "overwrite existing output file")

	rootCmd.AddCommand(suggestConfigCmd)
}

func runSuggestConfig(cmd *cobra.Command, args []string) error {
	opts := scanOptions{
		configPath:   suggestConfigPath,
		lndDir:       suggestLndDir,
		connectAddr:  suggestConnectAddr,
		macaroonPath: suggestMacaroonPath,
		tlsCertPath:  suggestTLSCertPath,
	}

	progress := func(string) {}
	r, warnings, err := executeScanWithOptions(opts, progress)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  ⚠  %s\n", w)
	}

	if suggestOutput == "" {
		return confgen.WriteSuggestedConfigPatch(os.Stdout, r.Findings)
	}

	if !suggestForce {
		if _, err := os.Stat(suggestOutput); err == nil {
			return fmt.Errorf("file %s already exists. Use --force to overwrite", suggestOutput)
		}
	}

	f, err := os.OpenFile(suggestOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	if err := confgen.WriteSuggestedConfigPatch(f, r.Findings); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Config suggestions written to %s\n", suggestOutput)
	return nil
}
