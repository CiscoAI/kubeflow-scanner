package vulns

import (
	"context"
	"time"

	"github.com/CiscoAI/kubeflow-scanner/pkg/scan/anchore"
	"github.com/spf13/cobra"
)

type flagpole struct {
	Image string
}

// NewCommand returns a new cobra.Command for vulns
func NewCommand() *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "vulns",
		Short: "List vulnerabilities for the registry.",
		Long:  "List vulnerabilities for the registry.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			//image := "gcr.io/kubeflow-images-public/tensorflow-1.14.0-notebook-gpu:v0.7.0"

			err := anchore.GetImageVulnerabilities(ctx, flags.Image)
			if err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&flags.Image, "image", "", "Image with Tag for vuln analysis")
	return cmd
}
