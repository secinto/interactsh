package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/secinto/interactsh/pkg/communication"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"git.mills.io/prologic/smtpd"
	jsoniter "github.com/json-iterator/go"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// SMTPServer is a smtp server instance that listens both
// TLS and Non-TLS based servers.
type SMTPServer struct {
	options     *Options
	smtpServer  smtpd.Server
	smtpsServer smtpd.Server
}

// NewSMTPServer returns a new TLS & Non-TLS SMTP server.
func NewSMTPServer(options *Options) (*SMTPServer, error) {
	server := &SMTPServer{options: options}

	authHandler := func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
		return true, nil
	}
	rcptHandler := func(remoteAddr net.Addr, from string, to string) bool {
		return true
	}
	server.smtpServer = smtpd.Server{
		Addr:        fmt.Sprintf("%s:%d", options.ListenIP, options.SmtpPort),
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domains[0],
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	server.smtpsServer = smtpd.Server{
		Addr:        fmt.Sprintf("%s:%d", options.ListenIP, options.SmtpsPort),
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domains[0],
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
	}
	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe(tlsConfig *tls.Config, smtpAlive, smtpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}
		srv := &smtpd.Server{Addr: fmt.Sprintf("%s:%d", h.options.ListenIP, h.options.SmtpAutoTLSPort), Handler: h.defaultHandler, Appname: "interactsh", Hostname: h.options.Domains[0]}
		srv.TLSConfig = tlsConfig

		smtpsAlive <- true
		err := srv.ListenAndServe()
		if err != nil {
			log.Errorf("Could not serve smtp with tls on port %d: %s\n", h.options.SmtpAutoTLSPort, err)
			smtpsAlive <- false
		}
	}()

	smtpAlive <- true
	go func() {
		if err := h.smtpServer.ListenAndServe(); err != nil {
			smtpAlive <- false
			log.Errorf("Could not serve smtp on port %d: %s\n", h.options.SmtpPort, err)
		}
	}()
	if err := h.smtpsServer.ListenAndServe(); err != nil {
		log.Errorf("Could not serve smtp on port %d: %s\n", h.options.SmtpsPort, err)
		smtpAlive <- false
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	atomic.AddUint64(&h.options.Stats.Smtp, 1)

	var uniqueID, fullID string

	dataString := string(data)
	log.Debugf("New SMTP request: %s %s %s %s\n", remoteAddr, from, to, dataString)

	// if root-tld is enabled stores any interaction towards the main domain
	for _, addr := range to {
		if h.options.RootTLD {
			for _, domain := range h.options.Domains {
				if stringsutil.HasSuffixI(addr, domain) {
					ID := domain
					host, _, _ := net.SplitHostPort(remoteAddr.String())
					address := addr[strings.LastIndex(addr, "@"):]
					interaction := &communication.Interaction{
						Protocol:      "smtp",
						UniqueID:      address,
						FullId:        address,
						RawRequest:    dataString,
						SMTPFrom:      from,
						RemoteAddress: host,
						Timestamp:     time.Now(),
					}
					buffer := &bytes.Buffer{}
					if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
						log.Debugf("Could not encode root tld SMTP interaction: %s\n", err)
					} else {
						log.Debugf("Root TLD SMTP Interaction: \n%s\n", buffer.String())
						if err := h.options.Storage.AddInteractionWithId(ID, buffer.Bytes()); err != nil {
							log.Debugf("Could not store root tld smtp interaction: %s\n", err)
						}
					}
				}
			}
		}
	}

	for _, addr := range to {
		if len(addr) > h.options.GetIdLength() && strings.Contains(addr, "@") {
			parts := strings.Split(addr[strings.LastIndex(addr, "@")+1:], ".")
			for i, part := range parts {
				if h.options.isCorrelationID(part) {
					uniqueID = part
					fullID = part
					if i+1 <= len(parts) {
						fullID = strings.Join(parts[:i+1], ".")
					}
				}
			}
		}
	}
	if uniqueID != "" {
		host, _, _ := net.SplitHostPort(remoteAddr.String())

		correlationID := uniqueID[:h.options.CorrelationIdLength]
		interaction := &communication.Interaction{
			Protocol:      "smtp",
			UniqueID:      uniqueID,
			FullId:        fullID,
			RawRequest:    dataString,
			SMTPFrom:      from,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			log.Debugf("Could not encode smtp interaction: %s\n", err)
		} else {
			log.Debugf("%s\n", buffer.String())
			if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
				log.Debugf("Could not store smtp interaction: %s\n", err)
			}
		}
	}
	return nil
}
