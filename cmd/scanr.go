package main

import (
	"os"

	"github.com/CiscoAI/kubeflow-scanner/cmd/scanr/image"
	"github.com/CiscoAI/kubeflow-scanner/cmd/scanr/k8s"
	"github.com/CiscoAI/kubeflow-scanner/cmd/scanr/kf"
	"github.com/CiscoAI/kubeflow-scanner/cmd/scanr/server"
	"github.com/CiscoAI/kubeflow-scanner/cmd/scanr/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const defaultLevel = log.WarnLevel

// Flags for the kind command
type Flags struct {
	LogLevel  string
	KfVersion string
	Registry  string
	Scanner   string
}

// NewCommand creates the root cobra command
func NewCommand() *cobra.Command {
	flags := &Flags{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "scanr",
		Short: "scanr is a tool for scanning Kubeflow artifacts",
		Long:  `scanr is a CLI tool for scanning Kubeflow images for vulnerabilities.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return runE(flags, cmd, args)
		},
		SilenceUsage: true,
	}
	// flags for the global command, scanr
	cmd.PersistentFlags().StringVar(&flags.LogLevel, "loglevel", "info", "Set global LogLevel for scanr.")
	cmd.PersistentFlags().StringVar(&flags.KfVersion, "kfversion", "v0.7", "Give the required version of Kubeflow.")
	cmd.PersistentFlags().StringVar(&flags.Registry, "registry", "gcr.io/kubeflow-images-public", "The image registry from where we pick the Kubeflow images.")
	cmd.PersistentFlags().StringVar(&flags.Scanner, "scanner", "anchore", "Choice of vulnerability scanner.")
	// sub-commands
	cmd.AddCommand(k8s.NewCommand())
	cmd.AddCommand(kf.NewCommand())
	cmd.AddCommand(image.NewCommand())
	cmd.AddCommand(server.NewCommand())
	cmd.AddCommand(version.NewCommand())
	return cmd
}

func runE(flags *Flags, cmd *cobra.Command, args []string) error {
	// handle logLevel logic
	level := defaultLevel
	parsed, err := log.ParseLevel(flags.LogLevel)
	if err != nil {
		log.Warnf("Invalid log level '%s', defaulting to '%s'", flags.LogLevel, level)
	} else {
		level = parsed
	}
	log.SetLevel(level)

	// handle registry logic
	// isGCR := false
	// log.Infof("is Repo GCR: %v", isGCR)

	// handle scanner logic
	return nil
}

// Run runs the `scanr` root command
func Run() error {
	return NewCommand().Execute()
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "15:04:05",
		ForceColors:     true,
	})
	if err := Run(); err != nil {
		os.Exit(1)
	}
}
