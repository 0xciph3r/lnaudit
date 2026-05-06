package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lnaudit",
	Short: "Security scanner for LND nodes",
	Long: `A security scanner that audits your Lightning Network Daemon configuration,
identifies misconfigurations, and provides actionable hardening recommendations.

Built for anyone running LND in production — solo operators, routing nodes,
exchanges, and custodians.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
