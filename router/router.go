package router

import (
	"net/http"

	commongin "github.com/equinor/radix-common/pkg/gin"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New creates a mux router for handling Github webhook requests
func New(webHookHandler http.Handler) http.Handler {
	engine := gin.New()
	engine.RemoveExtraSlash = true
	engine.Use(commongin.SetZerologLogger(commongin.ZerologLoggerWithRequestId))
	engine.Use(commongin.ZerologRequestLogger(), gin.Recovery())
	engine.Handle(http.MethodGet, "/health", func(ctx *gin.Context) {
		ctx.Writer.WriteHeader(http.StatusOK)
	})
	engine.Handle(http.MethodGet, "/metrics", gin.WrapH(promhttp.Handler()))
	engine.Handle(http.MethodPost, "/events/github", gin.WrapH(webHookHandler))
	engine.Handle(http.MethodPost, "/", gin.WrapH(webHookHandler))
	return engine
}
