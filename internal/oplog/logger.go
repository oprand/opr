package oplog

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

func New(logLevel zap.AtomicLevel, logDir, logFile string, forceConsole bool) (*zap.Logger, error) {
	return NewWithConsole(logLevel, logDir, logFile, forceConsole)
}

func LoggerFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "log-dir",
			Value:   ".",
			EnvVars: []string{"LOG_DIR"},
			Usage:   "Directory where to save logs.",
		},
		&cli.StringFlag{
			Name:    "log-file",
			Value:   "",
			EnvVars: []string{"LOG_FILE"},
			Usage:   "File where to save logs.",
		},
		&cli.StringFlag{
			Name:    "log-level",
			Value:   "info",
			EnvVars: []string{"LOG_LEVEL"},
			Usage:   "Log level, one of [debug|info|warn|error]",
		},
		&cli.BoolFlag{
			Name:    "log-console",
			Value:   false,
			EnvVars: []string{"LOG_CONSOLE"},
			Usage:   "Force logging to console/stdout (useful for Docker)",
		},
	}
}

func NewFromCli(c *cli.Context) (*zap.Logger, error) {
	var logLevel zap.AtomicLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	switch strings.ToLower(c.String("log-level")) {
	case "debug":
		logLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		logLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		logLevel = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		log.Println("invalid log-level value (must be on of debug|info|warn|error), defaulting to debug")
		logLevel = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	return NewWithConsole(logLevel, c.String("log-dir"), c.String("log-file"), c.Bool("log-console"))
}

func NewWithConsole(logLevel zap.AtomicLevel, logDir, logFile string, forceConsole bool) (*zap.Logger, error) {
	logPath := fmt.Sprintf("%s/%s", logDir, logFile)

	var cores []zapcore.Core

	// Log to console if the output is a terminal OR if forced
	if isTerminal(os.Stdout) || forceConsole {
		consoleConfig := zap.NewProductionEncoderConfig()
		consoleConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		consoleConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		cores = []zapcore.Core{
			zapcore.NewCore(zapcore.NewConsoleEncoder(consoleConfig), zapcore.AddSync(os.Stdout), logLevel),
		}
	}

	// add file output only if a logfile is set
	if logFile != "" {
		// create log dir if it does not exist
		if logDir != "" {
			if err := os.MkdirAll(filepath.Dir(logDir), 0740); err != nil {
				return nil, err
			}
		}
		fileConfig := zap.NewProductionEncoderConfig()
		fileConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		fileEncoder := zapcore.NewJSONEncoder(fileConfig)
		logFileDesc, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		cores = append(cores, zapcore.NewCore(fileEncoder, zapcore.AddSync(logFileDesc), logLevel))
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
