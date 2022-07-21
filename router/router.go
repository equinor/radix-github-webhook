package router

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func New(webHookHandler http.Handler) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")
	router.Handle("/metrics", promhttp.Handler())
	router.Handle("/events/github", webHookHandler)
	router.Handle("/", webHookHandler)
	return router
}
