package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/equinor/radix-github-webhook/handler"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
)

func getApiServerEndpoint() string {
	apiServerPrefix := os.Getenv("API_SERVER_ENDPOINT_PREFIX")
	clusterName := os.Getenv("RADIX_CLUSTERNAME")
	dnsZone := os.Getenv("RADIX_DNS_ZONE")

	return fmt.Sprintf("%s.%s.%s/api", apiServerPrefix, clusterName, dnsZone)
}

func main() {
	fs := initializeFlagSet()

	var (
		port              = fs.StringP("port", "p", defaultPort(), "The port for which we listen to events on")
		apiServerEndpoint = getApiServerEndpoint()
	)

	parseFlagsFromArgs(fs)

	token, err := getServiceAccountToken()
	if err != nil {
		logrus.Fatalf("Unable to read token from file: %v", err)
	}

	logrus.Infof("Listen for incoming events on port %s", *port)
	wh := handler.NewWebHookHandler(token, handler.NewAPIServerStub(apiServerEndpoint))

	router := mux.NewRouter()
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")
	router.Handle("/metrics", promhttp.Handler())
	router.Handle("/events/github", wh.HandleWebhookEvents())
	router.Handle("/", wh.HandleWebhookEvents())

	http.Handle("/", router)

	err = http.ListenAndServe(fmt.Sprintf(":%s", *port), nil)

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
	b, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", err
	}

	return string(b), nil
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
