package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/wgpsec/context1337/internal/api"
	"github.com/wgpsec/context1337/internal/config"
	mcphandler "github.com/wgpsec/context1337/internal/mcp"
	"github.com/wgpsec/context1337/internal/mcp/benchlog"
	"github.com/wgpsec/context1337/internal/storage"
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
	var toolMode string

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

			// Resolve tool-mode: flag > env var > default "lite"
			if !cmd.Flags().Changed("tool-mode") {
				if envMode := os.Getenv("ABOUTSECURITY_TOOL_MODE"); envMode != "" {
					toolMode = envMode
				}
			}
			switch mcphandler.ToolMode(toolMode) {
			case mcphandler.ToolModeLite, mcphandler.ToolModeFull:
				// valid
			default:
				return fmt.Errorf("invalid --tool-mode %q: must be \"lite\" or \"full\"", toolMode)
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

			mcpHandler := mcphandler.NewMCPServer(db, cfg.DataDir, mcphandler.ToolMode(toolMode))
			handler := api.NewRouter(db, cfg.DataDir, cfg.APIKey, mcpHandler)

			addr := fmt.Sprintf(":%d", cfg.Port)
			counts := storage.CountByType(db)
			log.Printf("absec server starting on %s (data: %s, tool-mode: %s)", addr, cfg.DataDir, toolMode)
			log.Printf("resources loaded: %d skills, %d dicts, %d payloads, %d tools, %d vulns",
				counts["skill"], counts["dict"], counts["payload"], counts["tool"], counts["vuln"])
			return http.ListenAndServe(addr, handler)
		},
	}

	cmd.Flags().IntVar(&port, "port", 8088, "HTTP listen port")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Data directory")
	cmd.Flags().BoolVar(&benchmark, "benchmark", false, "Enable MCP tool call logging")
	cmd.Flags().StringVar(&benchmarkScenario, "benchmark-scenario", "default", "Scenario label for benchmark logs")
	cmd.Flags().StringVar(&toolMode, "tool-mode", "lite", "Tool registration mode: lite (3 tools) or full (12 tools)")
	return cmd
}
