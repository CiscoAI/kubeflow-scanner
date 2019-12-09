package main

import (
	"os"

	image "github.com/CiscoAI/kubeflow-scanner/cmd/scanr/image"
	repo "github.com/CiscoAI/kubeflow-scanner/cmd/scanr/repo"
	version "github.com/CiscoAI/kubeflow-scanner/cmd/scanr/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const defaultLevel = log.WarnLevel

// Flags for the kind command
type Flags struct {
	LogLevel string
	Backend  string
}

// NewCommand creates the root cobra command
func NewCommand() *cobra.Command {
	flags := &Flags{LogLevel: "info"}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "scanr",
		Short: "scanr is a tool for scanning Kubeflow artifacts",
		Long: `
	scanr is a CLI tool for scanning Kubeflow images for vulnerabilities.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return runE(flags, cmd, args)
		},
		SilenceUsage: true,
		Version:      version.Version,
	}
	cmd.AddCommand(repo.NewCommand())
	cmd.AddCommand(image.NewCommand())
	cmd.AddCommand(version.NewCommand())
	return cmd
}

func runE(flags *Flags, cmd *cobra.Command, args []string) error {
	level := defaultLevel
	parsed, err := log.ParseLevel(flags.LogLevel)
	if err != nil {
		log.Warnf("Invalid log level '%s', defaulting to '%s'", flags.LogLevel, level)
	} else {
		level = parsed
	}
	log.SetLevel(level)
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
