package repo

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewCommand returns a new cobra.Command for repo
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "repo",
		Short: "Walk through the manifests repo and list all images",
		Long:  "Walk through the manifests repo and list all images",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("scanr repo TODO...")
			return nil
		},
	}
	return cmd
}
