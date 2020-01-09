package k8s

import (
	"github.com/CiscoAI/kubeflow-scanner/pkg/kubernetes"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type flagpole struct {
	Kubeconfig string
	Namespace  string
}

// NewCommand returns a new cobra.Command for repo
func NewCommand() *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "k8s",
		Short: "Walk through a k8s cluster and list vulnerabilities",
		Long:  "Walk through a k8s cluster and list vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return k8scan(cmd, args, flags)
		},
	}
	cmd.Flags().StringVar(&flags.Kubeconfig, "kubeconfig", "", "Point to Kubernetes cluster to be used")
	cmd.Flags().StringVar(&flags.Namespace, "namespace", "", "Kubernetes namespace to scan")
	return cmd
}

func k8scan(cmd *cobra.Command, args []string, flags *flagpole) error {
	report, err := kubernetes.ScanCluster(flags.Kubeconfig, flags.Namespace)
	if err != nil {
		return err
	}
	log.Infof("Vulnerability Report: %v", report)
	return nil
}
