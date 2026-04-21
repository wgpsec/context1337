package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Esonhugh/context1337/internal/api"
	"github.com/Esonhugh/context1337/internal/config"
	mcphandler "github.com/Esonhugh/context1337/internal/mcp"
	"github.com/Esonhugh/context1337/internal/mcp/benchlog"
	"github.com/Esonhugh/context1337/internal/storage"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "absec",
		Short:   "AboutSecurity MCP Server — pentest knowledge base",
		Version: version,
	}

	root.AddCommand(serveCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	var port int
	var dataDir string
	var benchmark bool
	var benchmarkScenario string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if port > 0 {
				os.Setenv("ABOUTSECURITY_PORT", fmt.Sprintf("%d", port))
			}
			if dataDir != "" {
				os.Setenv("ABOUTSECURITY_DATA_DIR", dataDir)
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			// Benchmark logging
			if benchmark {
				logDir := filepath.Join(cfg.DataDir, "benchmark")
				os.MkdirAll(logDir, 0o755)
				logPath := filepath.Join(logDir, "calls.jsonl")
				logger, err := benchlog.New(logPath, benchmarkScenario)
				if err != nil {
					return fmt.Errorf("init benchmark log: %w", err)
				}
				defer logger.Close()
				mcphandler.BenchLogger = logger
				log.Printf("benchmark: logging to %s (scenario: %s)", logPath, benchmarkScenario)
			}

			db, err := storage.InitRuntime(storage.LoaderConfig{
				BuiltinDB: cfg.BuiltinDB,
				RuntimeDB: cfg.RuntimeDB,
				TeamDir:   cfg.TeamDir,
			})
			if err != nil {
				return fmt.Errorf("init runtime: %w", err)
			}
			defer db.Close()

			mcpHandler := mcphandler.NewMCPServer(db, cfg.DataDir)
			handler := api.NewRouter(db, cfg.DataDir, cfg.APIKey, mcpHandler)

			addr := fmt.Sprintf(":%d", cfg.Port)
			log.Printf("absec server starting on %s (data: %s)", addr, cfg.DataDir)
			return http.ListenAndServe(addr, handler)
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "HTTP listen port")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Data directory")
	cmd.Flags().BoolVar(&benchmark, "benchmark", false, "Enable MCP tool call logging")
	cmd.Flags().StringVar(&benchmarkScenario, "benchmark-scenario", "default", "Scenario label for benchmark logs")
	return cmd
}
