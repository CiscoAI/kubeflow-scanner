package repo

import (
	"fmt"
	"regexp"

	"github.com/CiscoAI/kubeflow-scanner/pkg/resource"
	"github.com/CiscoAI/kubeflow-scanner/pkg/scan"
	"github.com/spf13/cobra"
)

type flagpole struct {
	Name           string
	GcpProjectName string
	OutputFileName string
	Filter         string
}

// NewCommand returns a new cobra.Command for repo
func NewCommand() *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "repo",
		Short: "Walk through the manifests repo and list all images",
		Long:  "Walk through the manifests repo and list all images",
		RunE: func(cmd *cobra.Command, args []string) error {
			return repo(cmd, args, flags)
		},
	}
	cmd.Flags().StringVar(&flags.Name, "name", "", "GCR repo name")
	cmd.Flags().StringVar(&flags.Filter, "filter", "", "Filter regex string")
	cmd.Flags().StringVar(&flags.GcpProjectName, "project", "", "GCP Project name")
	cmd.Flags().StringVar(&flags.OutputFileName, "file", "cvelist.yaml", "Output YAML filename")
	return cmd
}

func repo(cmd *cobra.Command, args []string, flags *flagpole) error {
	// fetch all images from repo, recursively
	imageList, err := resource.GetResourcesFromRepo(flags.Name, true)
	if err != nil {
		return fmt.Errorf("error fetching image list: %v", err)
	}
	regexID := regexp.MustCompile(flags.Filter)
	var newImageList []string
	for _, image := range imageList {
		if regexID.MatchString(image) {
			newImageList = append(newImageList, image)
		}
	}
	if err := scan.WriteVulnerabilitiesToFile(newImageList, flags.GcpProjectName, flags.OutputFileName); err != nil {
		return err
	}

	return nil
}
