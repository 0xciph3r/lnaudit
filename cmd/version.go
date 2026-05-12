package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	CommitSHA = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of lnaudit",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("lnaudit %s (commit: %s)\n", Version, CommitSHA)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
