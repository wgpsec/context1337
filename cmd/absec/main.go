package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wgpsec/context1337/internal/api"
	"github.com/wgpsec/context1337/internal/auth"
	"github.com/wgpsec/context1337/internal/buildinfo"
	"github.com/wgpsec/context1337/internal/config"
	"github.com/wgpsec/context1337/internal/fts"
	mcphandler "github.com/wgpsec/context1337/internal/mcp"
	"github.com/wgpsec/context1337/internal/mcp/benchlog"
	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "absec",
		Short:   "AboutSecurity MCP Server — pentest knowledge base",
		Version: buildinfo.Version,
	}

	root.AddCommand(serveCmd(), finalizeIndexCmd())
	return root
}

func finalizeIndexCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "finalize-index",
		Short: "Rebuild a resource database with the current FTS contract",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath == "" {
				return fmt.Errorf("--db is required")
			}
			if _, err := os.Stat(dbPath); err != nil {
				return fmt.Errorf("open index database: %w", err)
			}
			db, err := storage.OpenDB(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := fts.Reindex(db); err != nil {
				return fmt.Errorf("finalize index: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "Path to the resource SQLite database")
	return cmd
}

// exemptStreamingWrites clears the per-request write deadline for MCP streaming
// responses. mcp.StreamableHTTPHandler deliberately holds the response open —
// POST responses stream tool results over SSE, and the standalone GET stream
// stays open for the life of the session — so a server-level WriteTimeout would
// kill every stream once the deadline passes. ResponseController walks Unwrap
// to reach the real connection, which is why usage.responseWriter implements it.
//
// Only GET streams are exempted. A POST response ends when its tool call
// returns, and the 150KB maxResponseBytes ceiling keeps that bounded, so those
// stay under the server deadline.
func exemptStreamingWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStreamingRequest(r) {
			// Best effort: if the connection does not support deadlines the SDK
			// falls back to normal behavior, and the server timeout applies.
			_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		}
		next.ServeHTTP(w, r)
	})
}

func isStreamingRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

func serveCmd() *cobra.Command {
	var port int
	var dataDir string
	var benchmark bool
	var benchmarkScenario string
	var toolMode string
	var nucleiDir string
	var nucleiMinSeverity string

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

			// Flag wins over env var for nuclei settings
			if cmd.Flags().Changed("nuclei-dir") {
				cfg.NucleiDir = nucleiDir
			}
			if cmd.Flags().Changed("nuclei-min-severity") {
				cfg.NucleiMinSeverity = nucleiMinSeverity
			}

			// Benchmark logging
			if benchmark {
				logDir := filepath.Join(cfg.DataDir, "benchmark")
				// benchlog.New reports a missing parent dir, so the mkdir error
				// does not need handling of its own.
				_ = os.MkdirAll(logDir, 0o755)
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
				BuiltinDB:         cfg.BuiltinDB,
				RuntimeDB:         cfg.RuntimeDB,
				TeamDir:           cfg.TeamDir,
				NucleiDir:         cfg.NucleiDir,
				NucleiMinSeverity: cfg.NucleiMinSeverity,
			})
			if err != nil {
				return fmt.Errorf("init runtime: %w", err)
			}
			defer db.Close()

			keysFile := strings.TrimSpace(cfg.APIKeysFile)
			optionalKeysFile := false
			if keysFile == "" {
				keysFile = filepath.Join(cfg.DataDir, "runtime", "api-keys.json")
				optionalKeysFile = true
			}
			store, err := auth.Open(cfg.APIKey, keysFile, optionalKeysFile)
			if err != nil {
				return fmt.Errorf("load api keys: %w", err)
			}

			usageCollector := usage.NewCollector()
			mcpHandler := mcphandler.NewMCPServer(db, cfg.DataDir, mcphandler.ToolMode(toolMode), usageCollector)
			if err := auth.RequireIndependentAdminKey(store, cfg.AdminKey); err != nil {
				return err
			}
			handler := api.NewRouter(db, cfg.DataDir, store, mcpHandler, cfg.AdminKey, api.UsageEndpoint{
				Collector: usageCollector,
			})

			addr := fmt.Sprintf(":%d", cfg.Port)
			counts := storage.CountByType(db)
			log.Printf("absec server starting on %s (data: %s, tool-mode: %s)", addr, cfg.DataDir, toolMode)
			log.Printf("resources loaded: %d skills, %d dicts, %d payloads, %d vulns",
				counts["skill"], counts["dict"], counts["payload"], counts["vuln"])
			if cfg.NucleiDir != "" {
				log.Printf("nuclei-templates: %s (min-severity: %s)", cfg.NucleiDir, cfg.NucleiMinSeverity)
			}
			log.Printf("api keys file: %s", keysFile)
			if store.Enabled() {
				log.Printf("auth: %d principal(s) loaded (%s)", store.Count(), strings.Join(store.IDs(), ", "))
				log.Printf("usage analytics: enabled at GET /api/usage for write keys")
			} else {
				log.Printf("auth: disabled (development mode)")
			}
			if strings.TrimSpace(cfg.AdminKey) != "" {
				log.Printf("admin console: enabled at /admin")
			} else {
				log.Printf("admin console: disabled")
			}
			server := &http.Server{
				Addr:    addr,
				Handler: exemptStreamingWrites(handler),
				// ReadHeaderTimeout is the one that matters most: without it a
				// client that opens a connection and never finishes its headers
				// holds a goroutine and an fd forever (slowloris), and the
				// deployment sets no resource limits.
				ReadHeaderTimeout: 10 * time.Second,
				// Bodies here are small JSON documents; MaxBytesReader is not
				// wired up yet, so this is the only ceiling on upload size.
				ReadTimeout: 30 * time.Second,
				// Bounds a client that negotiates a response and then reads it
				// arbitrarily slowly. MCP's streaming responses are exempted
				// below, because they are meant to stay open indefinitely.
				WriteTimeout: 2 * time.Minute,
				IdleTimeout:  2 * time.Minute,
			}
			return server.ListenAndServe()
		},
	}

	cmd.Flags().IntVar(&port, "port", 1337, "HTTP listen port")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Data directory")
	cmd.Flags().BoolVar(&benchmark, "benchmark", false, "Enable MCP tool call logging")
	cmd.Flags().StringVar(&benchmarkScenario, "benchmark-scenario", "default", "Scenario label for benchmark logs")
	cmd.Flags().StringVar(&toolMode, "tool-mode", "lite", "Default tool mode when X-Tool-Mode header is absent: lite (3 tools) or full (12 tools). Clients can override per-request via X-Tool-Mode header.")
	cmd.Flags().StringVar(&nucleiDir, "nuclei-dir", "", "Path to nuclei-templates repo root (enables supported vulnerability templates when set)")
	cmd.Flags().StringVar(&nucleiMinSeverity, "nuclei-min-severity", "high", "Minimum severity for nuclei vulnerability import: critical|high|medium|low")
	return cmd
}
