package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/equinor/radix-github-webhook/handler"
	"github.com/equinor/radix-github-webhook/radix"
	"github.com/equinor/radix-github-webhook/router"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

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

func main() {
	fs := initializeFlagSet()

	var (
		port              = fs.StringP("port", "p", defaultPort(), "The port for which we listen to events on")
		apiServerEndpoint = getAPIServerEndpoint()
	)

	parseFlagsFromArgs(fs)

	token, err := getServiceAccountToken()
	if err != nil {
		logrus.Fatalf("Unable to read token from file: %v or from environment variable BEARER_TOKEN", err)
	}

	logrus.Infof("Listen for incoming events on port %s", *port)
	wh := handler.NewWebHookHandler(token, radix.NewAPIServerStub(apiServerEndpoint))
	router := router.New(wh.HandleWebhookEvents())
	err = http.ListenAndServe(fmt.Sprintf(":%s", *port), router)

	if err != nil {
		logrus.Fatalf("Unable to start serving: %v", err)
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

func getServiceAccountToken() (string, error) {
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err == nil {
		return string(token), nil
	}
	envToken := os.Getenv("BEARER_TOKEN")
	if len(envToken) != 0 {
		return envToken, nil
	}
	return "", err
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
