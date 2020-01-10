package k8s

import (
	"github.com/CiscoAI/kubeflow-scanner/pkg/kubernetes"
	"github.com/spf13/cobra"
)

type flagpole struct {
	OutputFilePath string
	Namespace      string
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
	cmd.Flags().StringVar(&flags.Namespace, "namespace", "", "Kubernetes namespace to scan")
	cmd.Flags().StringVar(&flags.OutputFilePath, "out", "vuln_report.yaml", "Output file path to save the vulnerability report")
	return cmd
}

func k8scan(cmd *cobra.Command, args []string, flags *flagpole) error {
	report, err := kubernetes.ScanCluster(flags.Namespace)
	if err != nil {
		return err
	}
	err = kubernetes.WriteReportToFile(flags.OutputFilePath, report)
	if err != nil {
		return err
	}
	return nil
}
