package server

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/genuinetools/reg/clair"
	"github.com/gorilla/mux"
	wordwrap "github.com/mitchellh/go-wordwrap"
	"github.com/shurcooL/httpfs/html/vfstemplate"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Reference implementation: https://github.com/genuinetools/reg/blob/master/server.go
// TODO(swiftdiaries): Change out implementation to take in a static file report and generate
// site instead of connecting to the registry and connecting to a Clair Server

type flagpole struct {
	GenerateAndExit bool

	Cert          string
	Key           string
	ListenAddress string
	Port          string
	AssetPath     string
}

// NewCommand returns a new cobra.Command for server
func NewCommand() *cobra.Command {
	flags := &flagpole{}
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "server",
		Short: "Generate a static site for a vulnerability report.",
		Long:  "Generate a static site for a vulnerability report.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			return runcmd(ctx, cmd, args, flags)
		},
	}
	cmd.Flags().StringVar(&flags.AssetPath, "assets", "", "Path to assets ")
	cmd.Flags().StringVar(&flags.ListenAddress, "addr", "0.0.0.0", "IP Address to serve the site")
	cmd.Flags().StringVar(&flags.Port, "port", "8080", "Port to serve the site")
	return cmd
}

func runcmd(ctx context.Context, cmd *cobra.Command, args []string, flags *flagpole) error {
	// Path to vulnerability report
	// TODO(swiftdiaries): read in the file, unmarshal to struct and fill up site template
	
	// Get the path to the asset directory.
	assetDir := flags.AssetPath
	if len(flags.AssetPath) <= 0 {
		assetDir, err := os.Getwd()
		if err != nil {
			return err
		}
	}

	staticDir := filepath.Join(assetDir, "static")

	funcMap := template.FuncMap{
		"trim": func(s string) string {
			return wordwrap.WrapString(s, 80)
		},
		"color": func(s string) string {
			switch s = strings.ToLower(s); s {
			case "high":
				return "danger"
			case "critical":
				return "danger"
			case "unknown":
				return "default"
			default:
				return "default"
			}
		},
	}

	rc.tmpl = template.New("").Funcs(funcMap)
	rc.tmpl = template.Must(vfstemplate.ParseGlob(templates.Assets, rc.tmpl, "*.html"))

	// Create the initial index.
	log.Info("creating initial static index")
	if err := rc.repositories(ctx, staticDir); err != nil {
		return fmt.Errorf("creating index failed: %v", err)
	}

	if cmd.generateAndExit {
		log.Info("output generated, exiting...")
		return nil
	}

	rc.interval = cmd.interval
	ticker := time.NewTicker(rc.interval)
	go func() {
		// Create more indexes every X minutes based off interval.
		for range ticker.C {
			log.Info("creating timer based static index")
			if err := rc.repositories(ctx, staticDir); err != nil {
				log.Warnf("creating static index failed: %v", err)
			}
		}
	}()

	// Create mux server.
	mux := mux.NewRouter()
	mux.UseEncodedPath()

	// Static files handler.
	mux.HandleFunc("/repo/{repo}/tags", rc.tagsHandler)
	mux.HandleFunc("/repo/{repo}/tags/", rc.tagsHandler)
	mux.HandleFunc("/repo/{repo}/tag/{tag}", rc.vulnerabilitiesHandler)
	mux.HandleFunc("/repo/{repo}/tag/{tag}/", rc.vulnerabilitiesHandler)

	// Add the vulns endpoints if we have a client for a clair server.
	if rc.cl != nil {
		log.Infof("adding clair handlers...")
		mux.HandleFunc("/repo/{repo}/tag/{tag}/vulns", rc.vulnerabilitiesHandler)
		mux.HandleFunc("/repo/{repo}/tag/{tag}/vulns/", rc.vulnerabilitiesHandler)
		mux.HandleFunc("/repo/{repo}/tag/{tag}/vulns.json", rc.vulnerabilitiesHandler)
	}

	// Serve the static assets.
	staticAssetsHandler := http.FileServer(static.Assets)
	mux.PathPrefix("/static/").Handler(http.StripPrefix("/static/", staticAssetsHandler))
	staticHandler := http.FileServer(http.Dir(staticDir))
	mux.Handle("/", staticHandler)

	// Set up the server.
	server := &http.Server{
		Addr:    cmd.listenAddress + ":" + cmd.port,
		Handler: mux,
	}
	log.Infof("Starting server on port %q", cmd.port)
	if len(cmd.cert) > 0 && len(cmd.key) > 0 {
		return server.ListenAndServeTLS(cmd.cert, cmd.key)
	}
	return server.ListenAndServe()
}
