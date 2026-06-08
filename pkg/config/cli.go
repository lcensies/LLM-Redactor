package config

type CommonConfig struct {
	BaseLogDir       string `help:"Base log directory" env:"LLM_REDACTOR_LOG_DIR" default:"~/.llm-redactor"`
	AppLogFile       string `help:"Application log file" env:"LLM_REDACTOR_APP_LOG_FILE" default:"app.jsonl"`
	TrafficLogFile   string `help:"Traffic log file" env:"LLM_REDACTOR_TRAFFIC_LOG_FILE" default:"traffic.jsonl"`
	DetectionLogFile string `help:"Detection log file" env:"LLM_REDACTOR_DETECTION_LOG_FILE" default:"detections.jsonl"`
	RedactorRules    string `help:"Redactor rules file (TOML or JSON)" env:"LLM_REDACTOR_REDACTOR_RULES" default:"~/.gitleaks.toml"`
	// If true, spool each full streaming response (SSE, NDJSON, etc.): origin bytes
	// to stream-debug/<id>.upstream.raw, client bytes after unredact to
	// stream-debug/<id>.raw, and index lines in stream-debug.jsonl.
	DebugStream bool   `help:"Log streaming responses under stream-debug/ (origin .upstream.raw + client .raw) (off by default)" env:"LLM_REDACTOR_DEBUG_STREAM" name:"debug-stream"`
	// Capture, when set, appends one JSON line per outbound (client→upstream)
	// request to the given file: {ts, method, url, body, body_raw?}. Off by default.
	Capture string `help:"Append one JSON line per outbound request to this file (full request capture; off by default)" env:"LLM_REDACTOR_CAPTURE" name:"capture" placeholder:"<file.jsonl>"`
	Version       bool   `help:"Show version information" short:"v"`
}

type ExecCLI struct {
	CommonConfig
	Host    string   `help:"Host" env:"LLM_REDACTOR_HOST" default:"127.0.0.1"`
	Port    int      `help:"Port" env:"LLM_REDACTOR_PORT" default:"0"`
	Command []string `arg:"" optional:"" help:"Command to execute"`
}

type ProxyCLI struct {
	CommonConfig
	Host string `help:"Host" env:"LLM_REDACTOR_HOST" default:"0.0.0.0"`
	Port int    `help:"Port" env:"LLM_REDACTOR_PORT" default:"4000"`
}
