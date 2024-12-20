package main

import (
	"bytes"
	"fmt"
	"github.com/secinto/interactsh/pkg/logging"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/secinto/interactsh/internal/runner"
	"github.com/secinto/interactsh/pkg/client"
	"github.com/secinto/interactsh/pkg/communication"
	"github.com/secinto/interactsh/pkg/options"
	"github.com/secinto/interactsh/pkg/settings"
)

var (
	healthcheck           bool
	defaultConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/interactsh-client/config.yaml")
	log                   = logging.NewLogger()
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	defaultOpts := client.DefaultOptions
	cliOptions := &options.CLIClientOptions{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Interactsh client - Go client to generate interactsh payloads and display interaction data.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&cliOptions.ServerURL, "server", "s", defaultOpts.ServerURL, "interactsh server(s) to use"),
	)

	flagSet.CreateGroup("config", "config",
		flagSet.StringVar(&cliOptions.Config, "config", defaultConfigLocation, "flag configuration file"),
		flagSet.DynamicVar(&cliOptions.PdcpAuth, "auth", "true", "configure projectdiscovery cloud (pdcp) api key"),
		flagSet.IntVarP(&cliOptions.NumberOfPayloads, "number", "n", 1, "number of interactsh payload to generate"),
		flagSet.StringVarP(&cliOptions.Token, "token", "t", "", "authentication token to connect protected interactsh server"),
		flagSet.IntVarP(&cliOptions.PollInterval, "poll-interval", "pi", 5, "poll interval in seconds to pull interaction data"),
		flagSet.BoolVarP(&cliOptions.DisableHTTPFallback, "no-http-fallback", "nf", false, "disable http fallback registration"),
		flagSet.IntVarP(&cliOptions.CorrelationIdLength, "correlation-id-length", "cidl", settings.CorrelationIdLengthDefault, "length of the correlation id preamble"),
		flagSet.IntVarP(&cliOptions.CorrelationIdNonceLength, "correlation-id-nonce-length", "cidn", settings.CorrelationIdNonceLengthDefault, "length of the correlation id nonce"),
		flagSet.StringVarP(&cliOptions.SessionFile, "session-file", "sf", "", "store/read from session file"),
		flagSet.DurationVarP(&cliOptions.KeepAliveInterval, "keep-alive-interval", "kai", time.Minute, "keep alive interval"),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.StringSliceVarP(&cliOptions.Match, "match", "m", nil, "match interaction based on the specified pattern", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&cliOptions.Filter, "filter", "f", nil, "filter interaction based on the specified pattern", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&cliOptions.DNSOnly, "dns-only", false, "display only dns interaction in CLI output"),
		flagSet.BoolVar(&cliOptions.HTTPOnly, "http-only", false, "display only http interaction in CLI output"),
		flagSet.BoolVar(&cliOptions.SmtpOnly, "smtp-only", false, "display only smtp interactions in CLI output"),
		flagSet.BoolVar(&cliOptions.Asn, "asn", false, " include asn information of remote ip in json output"),
	)

	flagSet.CreateGroup("custom", "Custom",
		flagSet.StringVarP(&cliOptions.Description, "desc", "d", "", "description for the created subdomains"),
		flagSet.StringVarP(&cliOptions.SetDescription, "set-desc", "sd", "", "sets description for given ID in the format ID:Description"),
		flagSet.BoolVarP(&cliOptions.QueryDescription, "get-desc", "gd", false, "gets descriptions, set -ss [ID] to search for given ID"),
		flagSet.BoolVarP(&cliOptions.QuerySessions, "get-sessions", "gs", false, "gets a list of sessions, set -ss [STRING] to filter by description"),
		flagSet.StringVarP(&cliOptions.QueryInteractions, "get-interactions", "gi", "", "gets a list of all interactions of given session"),
		flagSet.StringVarP(&cliOptions.SearchString, "search-string", "ss", "", "for use in conjunction with -gd, -gs"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(options.GetUpdateCallback("interactsh-client"), "update", "up", "update interactsh-client to latest version"),
		flagSet.BoolVarP(&cliOptions.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic interactsh-client update check"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVar(&cliOptions.Output, "o", "", "output file to write interaction data"),
		flagSet.BoolVar(&cliOptions.JSON, "json", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&cliOptions.StorePayload, "payload-store", "ps", false, "write generated interactsh payload to file"),
		flagSet.StringVarP(&cliOptions.StorePayloadFile, "payload-store-file", "psf", settings.StorePayloadFileDefault, "store generated interactsh payloads to given file"),

		flagSet.BoolVar(&cliOptions.Verbose, "v", false, "display verbose interaction"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&cliOptions.Version, "version", false, "show version of the project"),
		flagSet.BoolVarP(&healthcheck, "hc", "health-check", false, "run diagnostic check up"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse options: %s\n", err)
	}

	// If user have passed auth flag without key (ex: interactsh-client -auth)
	// then we will prompt user to enter the api key, if already set shows user identity and exit
	// If user have passed auth flag with key (ex: interactsh-client -auth=<api-key>)
	// then we will validate the key and save it to file
	if cliOptions.PdcpAuth == "true" {
		options.AuthWithPDCP()
	} else if len(cliOptions.PdcpAuth) == 36 {
		ph := pdcp.PDCPCredHandler{}
		if _, err := ph.GetCreds(); err == pdcp.ErrNoCreds {
			apiServer := env.GetEnvOrDefault("PDCP_API_SERVER", pdcp.DefaultApiServer)
			if validatedCreds, err := ph.ValidateAPIKey(cliOptions.PdcpAuth, apiServer, "interactsh"); err == nil {
				options.ShowBanner()
				asnmap.PDCPApiKey = validatedCreds.APIKey
				if err = ph.SaveCreds(validatedCreds); err != nil {
					log.Debugf("Could not save credentials to file: %s\n", err)
				}
			}
		}
	} else {
		options.ShowBanner()
	}

	if healthcheck {
		cfgFilePath, _ := flagSet.GetConfigFilePath()
		log.Infof("%s\n", runner.DoHealthCheck(cfgFilePath))
		os.Exit(0)
	}
	if cliOptions.Version {
		log.Infof("Current Version: %s\n", options.Version)
		os.Exit(0)
	}

	if !cliOptions.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("interactsh-client", options.Version)()
		if err != nil {
			if cliOptions.Verbose {
				log.Errorf("interactsh version check failed: %v", err.Error())
			}
		} else {
			log.Infof("Current interactsh version %v %v", options.Version, updateutils.GetVersionDescription(options.Version, latestVersion))
		}
	}

	if cliOptions.Config != defaultConfigLocation {
		if err := flagSet.MergeConfigFile(cliOptions.Config); err != nil {
			log.Fatalf("Could not read config: %s\n", err)
		}
	}

	var outputFile *os.File
	var err error
	if cliOptions.Output != "" {
		if outputFile, err = os.Create(cliOptions.Output); err != nil {
			log.Fatalf("Could not create output file: %s\n", err)
		}
		defer outputFile.Close()
	}

	var sessionInfo *options.SessionInfo
	if fileutil.FileExists(cliOptions.SessionFile) {
		// attempt to load session info - silently ignore on failure
		_ = fileutil.Unmarshal(fileutil.YAML, []byte(cliOptions.SessionFile), &sessionInfo)
	}

	options := &client.Options{
		ServerURL:                cliOptions.ServerURL,
		Token:                    cliOptions.Token,
		DisableHTTPFallback:      cliOptions.DisableHTTPFallback,
		CorrelationIdLength:      cliOptions.CorrelationIdLength,
		CorrelationIdNonceLength: cliOptions.CorrelationIdNonceLength,
		SessionInfo:              sessionInfo,
		Description:              cliOptions.Description,
	}
	// show all interactions
	noFilter := !cliOptions.DNSOnly && !cliOptions.HTTPOnly && !cliOptions.SmtpOnly

	var matcher *regexMatcher
	var filter *regexMatcher
	if len(cliOptions.Match) > 0 {
		if matcher, err = newRegexMatcher(cliOptions.Match); err != nil {
			log.Fatalf("Could not compile matchers: %s\n", err)
		}
	}
	if len(cliOptions.Filter) > 0 {
		if filter, err = newRegexMatcher(cliOptions.Filter); err != nil {
			log.Fatalf("Could not compile filter: %s\n", err)
		}
	}

	printFunction := func(interaction *communication.Interaction) {
		if matcher != nil && !matcher.match(interaction.FullId) {
			return
		}
		if filter != nil && filter.match(interaction.FullId) {
			return
		}

		if !cliOptions.JSON {
			builder := &bytes.Buffer{}

			switch interaction.Protocol {
			case "dns":
				if noFilter || cliOptions.DNSOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received DNS interaction (%s) from %s at %s", interaction.FullId, interaction.QType, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n-----------\nDNS Request\n-----------\n\n%s\n\n------------\nDNS Response\n------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "http":
				if noFilter || cliOptions.HTTPOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received HTTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nHTTP Request\n------------\n\n%s\n\n-------------\nHTTP Response\n-------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "smtp":
				if noFilter || cliOptions.SmtpOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received SMTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nSMTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "ftp":
				if noFilter {
					builder.WriteString(fmt.Sprintf("Received FTP interaction from %s at %s", interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nFTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "responder", "smb":
				if noFilter {
					builder.WriteString(fmt.Sprintf("Received Responder/Smb interaction at %s", interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nResponder/SMB Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			case "ldap":
				if noFilter {
					builder.WriteString(fmt.Sprintf("[%s] Received LDAP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nLDAP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			}
		} else {
			b, err := jsoniter.Marshal(interaction)
			if err != nil {
				log.Errorf("Could not marshal json output: %s\n", err)
			} else {
				os.Stdout.Write(b)
				os.Stdout.Write([]byte("\n"))
			}
			if outputFile != nil {
				_, _ = outputFile.Write(b)
				_, _ = outputFile.Write([]byte("\n"))
			}
		}
	}

	if cliOptions.QueryDescription {
		descriptions, err := client.DescriptionQuery(options, cliOptions.SearchString)
		if err != nil {
			log.Fatalf("Could not fetch Descriptions: %s\n", err)
		}
		printDescriptions(descriptions)

		os.Exit(0)
	}
	if cliOptions.QuerySessions {
		sessions, err := client.SessionQuery(options, "", "", cliOptions.SearchString)
		if err != nil {
			log.Fatalf("Could not fetch sessions: %s\n", err)
		}

		printSessions(sessions)
		os.Exit(0)
	}

	if cliOptions.SetDescription != "" {
		if len(strings.Split(cliOptions.SetDescription, ":")) != 2 {
			log.Fatalf("Wrong format! Use ID:Description")
		}
		if err := client.SetDesc(options, cliOptions.SetDescription); err != nil {
			log.Fatalf("Could not set new description: %s\n", err)
		}

		log.Infof("Description updated successfully!")
		os.Exit(0)
	}

	if cliOptions.QueryInteractions != "" {
		response, err := client.InteractionQuery(options, cliOptions.QueryInteractions)
		if err != nil {
			log.Fatalf("Could not get interactions: %s\n", err)
		}

		for _, interactionData := range response.Data {
			interaction := &communication.Interaction{}

			if err := jsoniter.Unmarshal([]byte(interactionData), interaction); err != nil {
				log.Errorf("Could not unmarshal interaction data interaction: %v\n", err)
				continue
			}
			printFunction(interaction)
		}
		os.Exit(0)
	}

	client, err := client.New(options)
	if err != nil {
		log.Fatalf("Could not create client: %s\n", err)
	}

	interactshURLs := generatePayloadURL(cliOptions.NumberOfPayloads, client)

	log.Infof("Listing %d payload for OOB Testing\n", cliOptions.NumberOfPayloads)
	for _, interactshURL := range interactshURLs {
		log.Infof("%s\n", interactshURL)
	}

	if cliOptions.StorePayload && cliOptions.StorePayloadFile != "" {
		if err := os.WriteFile(cliOptions.StorePayloadFile, []byte(strings.Join(interactshURLs, "\n")), 0644); err != nil {
			log.Fatalf("Could not write to payload output file: %s\n", err)
		}
	}

	err = client.StartPolling(time.Duration(cliOptions.PollInterval)*time.Second, printFunction)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		if cliOptions.SessionFile != "" {
			_ = client.SaveSessionTo(cliOptions.SessionFile)
		}
		_ = client.StopPolling()
		// whether the session is saved/loaded it shouldn't be destroyed {
		if cliOptions.SessionFile == "" {
			client.Close()
		}
		os.Exit(1)
	}
}

const descSize = 50

func printDescriptions(descriptions []*communication.DescriptionEntry) {
	log.Debugf("\n%20s %10s %*s\n", "ID", "Date", descSize, "DESCRIPTION")
	for i := range descriptions {
		descChunks := client.SplitChunks(descriptions[i].Description, descSize)
		log.Debugf("%20s %10s %*s\n", descriptions[i].CorrelationID, descriptions[i].Date, descSize, descChunks[0])
		for i := 1; i < len(descChunks); i++ {
			log.Debugf("%20s %10s %*s\n", "", "", descSize, descChunks[i])
		}
	}
}

func printSessions(sessions []*communication.SessionEntry) {
	log.Debugf("\n%20s %20s %20s %*s\n", "ID", "Registered At", "Deregistered At", descSize, "Description")
	for i := range sessions {
		descChunks := client.SplitChunks(sessions[i].Description, descSize)
		log.Debugf("%20s %20s %20s %*s\n", sessions[i].ID, sessions[i].RegisterDate, sessions[i].DeregisterDate, descSize, descChunks[0])
		for i := 1; i < len(descChunks); i++ {
			log.Debugf("%20s %20s %20s %*s\n", "", "", "", descSize, descChunks[i])
		}
	}
}

func generatePayloadURL(numberOfPayloads int, client *client.Client) []string {
	interactshURLs := make([]string, numberOfPayloads)
	for i := 0; i < numberOfPayloads; i++ {
		interactshURLs[i] = client.URL()
	}
	return interactshURLs
}

func writeOutput(outputFile *os.File, builder *bytes.Buffer) {
	if outputFile != nil {
		_, _ = outputFile.Write(builder.Bytes())
		_, _ = outputFile.Write([]byte("\n"))
	}
	log.Infof("%s", builder.String())
}

type regexMatcher struct {
	items []*regexp.Regexp
}

func newRegexMatcher(items []string) (*regexMatcher, error) {
	matcher := &regexMatcher{}
	for _, item := range items {
		if compiled, err := regexp.Compile(item); err != nil {
			return nil, err
		} else {
			matcher.items = append(matcher.items, compiled)
		}
	}
	return matcher, nil
}

func (m *regexMatcher) match(item string) bool {
	for _, regex := range m.items {
		if regex.MatchString(item) {
			return true
		}
	}
	return false
}
