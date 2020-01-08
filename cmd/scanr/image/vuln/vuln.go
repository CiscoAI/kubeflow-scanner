package vuln

import (
	"context"
	"fmt"
	"time"

	"github.com/CiscoAI/kubeflow-scanner/pkg/scan/anchore"
	"github.com/spf13/cobra"
)

// NewCommand returns a new cobra.Command for fetching image vulns
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln",
		Short: "Lists the vulnerabilities for the image",
		Long:  "Lists the vulnerabilities for the image",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("Insufficient arguments, retry with the image name as argument")
			} else if len(args) > 1 {
				return fmt.Errorf("Too many arguments, retry with the image name as the only argument")
			}
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			err := anchore.GetVuln(ctx, args[0])
			if err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}
