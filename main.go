package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/equinor/radix-github-webhook/handler"
	"github.com/equinor/radix-github-webhook/internal"
	"github.com/equinor/radix-github-webhook/radix"
	"github.com/equinor/radix-github-webhook/router"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"
)

const serviceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func main() {
	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)

	fs := initializeFlagSet()
	var (
		port              = fs.StringP("port", "p", defaultPort(), "The port for which we listen to events on")
		apiServerEndpoint = getAPIServerEndpoint()
	)
	parseFlagsFromArgs(fs)

	tokenSource, err := getTokenSource()
	if err != nil {
		log.Fatal(err)
	}

	client := oauth2.NewClient(context.Background(), oauth2.ReuseTokenSource(nil, tokenSource))
	wh := handler.NewWebHookHandler(radix.NewAPIServerStub(apiServerEndpoint, client))
	router := router.New(wh.HandleWebhookEvents())
	err = http.ListenAndServe(fmt.Sprintf(":%s", *port), router)

	if err != nil {
		log.Fatalf("Unable to start serving: %v", err)
	}
}

func initializeFlagSet() *pflag.FlagSet {
	// Flag domain.
	fs := pflag.NewFlagSet("default", pflag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "DESCRIPTION\n")
		fmt.Fprintf(os.Stderr, "  radix webhook.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		fs.PrintDefaults()
	}
	return fs
}

func getAPIServerEndpoint() string {
	envUseLocalRadixAPI := os.Getenv("USE_LOCAL_RADIX_API")
	useLocalRadixAPI := strings.EqualFold(envUseLocalRadixAPI, "yes") || strings.EqualFold(envUseLocalRadixAPI, "true")
	if useLocalRadixAPI {
		return "http://localhost:3002/api"
	}

	apiServerPrefix := os.Getenv("API_SERVER_ENDPOINT_PREFIX")
	clusterName := os.Getenv("RADIX_CLUSTERNAME")
	dnsZone := os.Getenv("RADIX_DNS_ZONE")
	return fmt.Sprintf("%s.%s.%s/api", apiServerPrefix, clusterName, dnsZone)
}

func getTokenSource() (oauth2.TokenSource, error) {
	if _, err := os.Stat(serviceAccountTokenFile); err == nil {
		return internal.JwtCallbackTokenSource(func() (string, error) {
			token, err := os.ReadFile(serviceAccountTokenFile)
			return string(token), err
		}), nil
	}

	envToken := os.Getenv("BEARER_TOKEN")
	if len(envToken) > 0 {
		return internal.JwtCallbackTokenSource(func() (string, error) { return envToken, nil }), nil
	}
	return nil, errors.New("failed to create TokenSource from mounted service account token or environment variable")
}

func parseFlagsFromArgs(fs *pflag.FlagSet) {
	err := fs.Parse(os.Args[1:])
	switch {
	case err == pflag.ErrHelp:
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "Error: %s\n\n", err.Error())
		fs.Usage()
		os.Exit(2)
	}
}

func defaultPort() string {
	return "3001"
}
