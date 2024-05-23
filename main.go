package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/equinor/radix-github-webhook/handler"
	"github.com/equinor/radix-github-webhook/internal"
	"github.com/equinor/radix-github-webhook/radix"
	"github.com/equinor/radix-github-webhook/router"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"os/signal"

	"github.com/spf13/pflag"
	"golang.org/x/oauth2"
)

const (
	serviceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultPort             = "3001"
	defaultMetricsPort      = "9090"
)

func main() {
	fs := initializeFlagSet()
	var (
		port              = fs.StringP("port", "p", defaultPort, "The port for which we listen to events on")
		metricPort        = fs.String("metrics-port", defaultMetricsPort, "The metrics API server port")
		apiServerEndpoint = getAPIServerEndpoint()
	)
	parseFlagsFromArgs(fs)

	setupLogger()

	srv, err := initializeServer(*port, apiServerEndpoint)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize API server")
	}

	metricsSrv := initializeMetricsServer(*metricPort)

	startServers(srv, metricsSrv)

	shutdownServersGracefulOnSignal(srv, metricsSrv)
}

func startServers(servers ...*http.Server) {
	for _, srv := range servers {
		go func() {
			log.Info().Msgf("Starting server on address %s", srv.Addr)
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				log.Fatal().Err(err).Msgf("Unable to start server on address %s", srv.Addr)
			}
		}()
	}
}

func shutdownServersGracefulOnSignal(servers ...*http.Server) {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGTERM, syscall.SIGINT)
	s := <-stopCh
	log.Info().Msgf("Received %v signal", s)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	for _, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info().Msgf("Shutting down server on address %s", srv.Addr)
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Warn().Err(err).Msgf("shutdown of server on address %s returned an error", srv.Addr)
			}
		}()
	}

	wg.Wait()
}

func initializeServer(port, apiServerEndpoint string) (*http.Server, error) {
	log.Info().Msgf("Initializing API server on port %s", port)

	tokenSource, err := getTokenSource()
	if err != nil {
		return nil, fmt.Errorf("failed to get tokenSource: %w", err)
	}

	client := oauth2.NewClient(context.Background(), oauth2.ReuseTokenSource(nil, tokenSource))
	wh := handler.NewWebHookHandler(radix.NewAPIServerStub(apiServerEndpoint, client))
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: router.NewWebhook(wh),
	}

	return srv, nil
}

func initializeMetricsServer(port string) *http.Server {
	log.Info().Msgf("Initializing metrics server on port %s", port)
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: router.NewMetrics(),
	}
	return srv
}

func setupLogger() {
	level := os.Getenv("LOG_LEVEL")
	pretty, _ := strconv.ParseBool(os.Getenv("LOG_PRETTY"))

	var logWriter io.Writer = os.Stderr
	if pretty {
		logWriter = &zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.TimeOnly}
	}

	logLevel, err := zerolog.ParseLevel(level)
	if err != nil || logLevel == zerolog.NoLevel {
		logLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(logLevel)
	log.Logger = zerolog.New(logWriter).With().Timestamp().Logger()
	zerolog.DefaultContextLogger = &log.Logger
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
		fmt.Fprintf(os.Stderr, "ApiError: %s\n\n", err.Error())
		fs.Usage()
		os.Exit(2)
	}
}
