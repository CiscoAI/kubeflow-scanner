package server

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewCommand returns a new cobra.Command for server
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "server",
		Short: "Run a static UI server for a registry.",
		Long:  "Run a static UI server for a registry.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("server called...")
			return nil
		},
	}
	return cmd
}
