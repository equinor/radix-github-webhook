package router

import (
	"net/http"

	commongin "github.com/equinor/radix-common/pkg/gin"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewWebhook creates a mux router for handling Github webhook requests
func NewWebhook(webHookHandler gin.HandlerFunc) http.Handler {
	engine := gin.New()
	engine.RemoveExtraSlash = true
	engine.Use(commongin.SetZerologLogger(commongin.ZerologLoggerWithRequestId))
	engine.Use(commongin.ZerologRequestLogger(), gin.Recovery())
	engine.Handle(http.MethodGet, "/health", func(ctx *gin.Context) {
		ctx.Writer.WriteHeader(http.StatusOK)
	})
	engine.Handle(http.MethodPost, "/events/github", webHookHandler)
	engine.Handle(http.MethodPost, "/", webHookHandler)
	return engine
}

// NewWebhook creates a mux router for handling Github webhook requests
func NewMetrics() http.Handler {
	engine := gin.New()
	engine.RemoveExtraSlash = true
	engine.Use(commongin.SetZerologLogger(commongin.ZerologLoggerWithRequestId))
	engine.Use(commongin.ZerologRequestLogger(), gin.Recovery())
	engine.Handle(http.MethodGet, "/metrics", gin.WrapH(promhttp.Handler()))
	return engine
}
