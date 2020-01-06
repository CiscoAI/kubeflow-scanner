package vulns

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewCommand returns a new cobra.Command for vulns
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "vulns",
		Short: "List vulnerabilities for the registry.",
		Long:  "List vulnerabilities for the registry.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("vulns called...")
			return nil
		},
	}
	return cmd
}
