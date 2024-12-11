package options

import (
	"github.com/projectdiscovery/utils/auth/pdcp"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/secinto/interactsh/pkg/logging"
)

const Version = "1.2.2"

var (
	banner = (`
    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/
`)
	log = logging.NewLogger()
)

func ShowBanner() {
	log.Infof("%s\n", banner)
	log.Infof("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates interactsh
func GetUpdateCallback(assetName string) func() {
	return func() {
		ShowBanner()
		updateutils.GetUpdateToolFromRepoCallback(assetName, Version, "interactsh")()
	}
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	ShowBanner()
	pdcp.CheckNValidateCredentials("interactsh")
}
