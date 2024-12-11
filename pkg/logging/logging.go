package logging

import (
	"fmt"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/mattn/go-colorable"
	"github.com/secinto/elasticPusher/pusher"
	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	"github.com/spf13/viper"
	"os"
)

var (
	viperConfigured = false
	logLevel        logrus.Level
)

type Logger struct{ *logrus.Logger }

type Fields = logrus.Fields

func NewLogger() *Logger {
	if !viperConfigured {
		ReadViperConfig()
	}

	configLogLevel := viper.GetString("server.logLevel")

	if configLogLevel == "debug" {
		logLevel = logrus.DebugLevel
	} else if configLogLevel == "info" {
		logLevel = logrus.InfoLevel
	} else if configLogLevel == "warn" {
		logLevel = logrus.WarnLevel
	} else if configLogLevel == "error" {
		logLevel = logrus.ErrorLevel
	} else if configLogLevel == "trace" {
		logLevel = logrus.TraceLevel
	} else if configLogLevel == "fatal" {
		logLevel = logrus.FatalLevel
	} else if configLogLevel == "panic" {
		logLevel = logrus.PanicLevel
	} else {
		logLevel = logrus.DebugLevel
	}
	return NewLoggerWithLevel(logLevel)
}

func NewLoggerWithLevel(logLevel logrus.Level) *Logger {

	log := logrus.New()
	log.SetLevel(logLevel)

	rotateFileHook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   "logs/console.log",
		MaxSize:    50, // megabytes
		MaxBackups: 3,  // amouts
		MaxAge:     28, //days
		Level:      logLevel,
		Formatter: &logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		},
	})

	if err != nil {
		logrus.Fatalf("Failed to initialize file rotate hook: %v", err)
	}

	log.SetOutput(colorable.NewColorableStdout())

	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText:    true,
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	cfg := elasticsearch.Config{
		Addresses: []string{
			"https://192.168.195.150:9200",
		},
		CertificateFingerprint: "0B481F3C76DB57706C4DB6BA6514F6E9DE344F6212CAFE5B847E7D705AE6A591",
	}

	elasticAPIKey := viper.GetString("elasticsearch.apiKey")
	if elasticAPIKey == "" {
		cfg.Username = viper.GetString("elasticsearch.username")
		cfg.Password = viper.GetString("elasticsearch.password")
	} else {
		cfg.APIKey = elasticAPIKey
	}
	host := viper.GetString("server.url")
	pusherClient, err := pusher.FromConfig(cfg, "checkfix_app", host)
	if err != nil {
		log.Errorf("Couldn't add ELK logger: %v", err)
	}

	pusherHook := pusher.Hook{
		Pusher:   pusherClient,
		LogLevel: logLevel,
		Formatter: &logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		},
	}
	log.Hooks.Add(&pusherHook)
	log.AddHook(rotateFileHook)

	return &Logger{log}
}

func ReadViperConfig() {
	viper.SetConfigFile("static/config.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("couldn't read config file: ", err)
		os.Exit(-1)
	} else {
		viperConfigured = true
	}
}
