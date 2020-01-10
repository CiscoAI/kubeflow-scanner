package kf

import (
	"github.com/CiscoAI/kubeflow-scanner/pkg/kubernetes"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type flagpole struct {
	KFDef      string
	Kubeconfig string
	Namespace  string
}

// NewCommand returns a new cobra.Command for repo
func NewCommand() *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "kf",
		Short: "Walk through the images in a Kubeflow deployment and list vulnerabilities",
		Long:  "Walk through the images in a Kubeflow deployment and list vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return kfscan(cmd, args, flags)
		},
	}
	cmd.Flags().StringVar(&flags.KFDef, "kfdef", "", "KFDef for Kubeflow deployment")
	cmd.Flags().StringVar(&flags.Kubeconfig, "kubeconfig", "", "Point to Kubernetes cluster to be used")
	cmd.Flags().StringVar(&flags.Namespace, "namespace", "kubeflow", "Kubernetes namespace to scan")
	return cmd
}

func kfscan(cmd *cobra.Command, args []string, flags *flagpole) error {
	report, err := kubernetes.ScanCluster(flags.Namespace)
	if err != nil {
		return err
	}
	log.Infof("Vulnerability Report: %v", report)
	return nil
}
