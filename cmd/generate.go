package cmd

import (
	"fmt"
	"os"

	"github.com/NonsoAmadi10/lnaudit/pkg/confgen"
	"github.com/spf13/cobra"
)

var (
	genOutput     string
	genNetwork    string
	genProfile    string
	genTor        bool
	genWatchtower string
	genAlias      string
	genForce      bool
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a hardened lnd.conf template",
	Long: `Generate a security-hardened LND configuration file based on best
practices derived from real-world Bitcoin infrastructure incidents.

The output is a starter template — review and merge with your existing
configuration before use. Node-specific settings (chain backend, wallet
paths, fee policies) are not included.

Examples:
  lnaudit generate                              # print to stdout (routing profile)
  lnaudit generate --profile private            # for wallet/private nodes
  lnaudit generate --output hardened.conf        # write to file
  lnaudit generate --tor                         # include Tor config
  lnaudit generate --network testnet             # for testnet
  lnaudit generate --watchtower <pubkey>@host    # include watchtower URI
  lnaudit generate --alias "my-node"             # set node alias`,
	RunE: runGenerate,
}

func init() {
	generateCmd.Flags().StringVarP(&genOutput, "output", "o", "", "write config to file instead of stdout")
	generateCmd.Flags().StringVar(&genNetwork, "network", "mainnet", "bitcoin network: mainnet, testnet, regtest, signet")
	generateCmd.Flags().StringVar(&genProfile, "profile", "routing", "security profile: routing (public node) or private (wallet node)")
	generateCmd.Flags().BoolVar(&genTor, "tor", false, "include Tor configuration section")
	generateCmd.Flags().StringVar(&genWatchtower, "watchtower", "", "watchtower URI (pubkey@host:port)")
	generateCmd.Flags().StringVar(&genAlias, "alias", "", "node alias")
	generateCmd.Flags().BoolVar(&genForce, "force", false, "overwrite existing output file")

	rootCmd.AddCommand(generateCmd)
}

func runGenerate(cmd *cobra.Command, args []string) error {
	opts := confgen.Options{
		Network:    genNetwork,
		Tor:        genTor,
		Watchtower: genWatchtower,
		Alias:      genAlias,
	}

	// Validate profile
	switch genProfile {
	case "routing":
		opts.Profile = confgen.ProfileRouting
	case "private":
		opts.Profile = confgen.ProfilePrivate
	default:
		return fmt.Errorf("invalid profile %q: use 'routing' or 'private'", genProfile)
	}

	// Validate network
	validNetworks := map[string]bool{
		"mainnet": true, "testnet": true, "regtest": true, "signet": true, "simnet": true,
	}
	if !validNetworks[opts.Network] {
		return fmt.Errorf("invalid network %q: use mainnet, testnet, regtest, or signet", opts.Network)
	}

	// Write to file or stdout
	if genOutput != "" {
		return writeToFile(opts)
	}

	return confgen.Generate(os.Stdout, opts)
}

func writeToFile(opts confgen.Options) error {
	// Check if file exists
	if !genForce {
		if _, err := os.Stat(genOutput); err == nil {
			return fmt.Errorf("file %s already exists. Use --force to overwrite", genOutput)
		}
	}

	f, err := os.OpenFile(genOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	if err := confgen.Generate(f, opts); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Hardened configuration written to %s (mode 0600)\n", genOutput)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Next steps:")
	fmt.Fprintln(os.Stderr, "  1. Review the generated config and merge with your existing lnd.conf")
	fmt.Fprintln(os.Stderr, "  2. Complete the post-generation checklist at the bottom of the file")
	fmt.Fprintln(os.Stderr, "  3. Validate: lnaudit scan --config", genOutput)

	return nil
}
