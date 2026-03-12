package commands

import (
	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/redactor"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
)

func Sync(cli *config.CLI, logs *logging.Loggers) {
	if err := redactor.DownloadRules(cli.RedactorRules, cli.Sync.URL, logs.System); err != nil {
		logs.System.Fatal().Err(err).Msg("failed to sync rules")
	}
	logs.System.Info().Msg("sync completed")
}
