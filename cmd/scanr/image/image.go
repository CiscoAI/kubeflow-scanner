package image

import (
	"github.com/CiscoAI/kubeflow-scanner/pkg/scan"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type flagpole struct {
	Image      string
	GcpProject string
}

// NewCommand returns a new cobra.Command for version
func NewCommand() *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "image",
		Short: "Scans an image and errors out if it has vulnerabilities",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rune(cmd, args, flags)
		},
	}
	cmd.Flags().StringVar(&flags.Image, "image", "", "image name")
	cmd.Flags().StringVar(&flags.GcpProject, "project", "", "GCP Project Name")
	return cmd
}

func rune(cmd *cobra.Command, args []string, flags *flagpole) error {
	occurenceList, err := scan.FindVulnerabilityOccurrencesForImage("https://"+flags.Image, flags.GcpProject)
	if err != nil {
		return err
	}
	if len(occurenceList) == 0 {
		log.Infof("No vulnerabilties found for resource: %v\n\n", flags.Image)
	} else {
		log.Fatalf("image: %v has HIGH, CRITICAL vulnerabilties", flags.Image)
	}
	return nil
}
