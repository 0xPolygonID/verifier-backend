package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/0xPolygonID/verifier-backend/internal/api"
	"github.com/0xPolygonID/verifier-backend/internal/config"
	"github.com/0xPolygonID/verifier-backend/internal/errors"
	"github.com/0xPolygonID/verifier-backend/internal/metrics"
)

func main() {
	registerMetrics()

	cfg, err := config.Load()
	if err != nil {
		log.WithField("error", err).Error("cannot load config")
		return
	}

	keysLoader := &loaders.FSKeyLoader{Dir: cfg.KeyDIR}

	mux := chi.NewRouter()
	mux.Use(
		metrics.PrometheusTotalRequestsMiddleware,
		chiMiddleware.RequestID,
		chiMiddleware.Recoverer,
		cors.Handler(cors.Options{AllowedOrigins: []string{"*"}}),
		chiMiddleware.NoCache,
	)

	apiServer := api.New(*cfg, keysLoader)
	api.HandlerFromMux(api.NewStrictHandlerWithOptions(apiServer, nil,
		api.StrictHTTPServerOptions{RequestErrorHandlerFunc: errors.RequestErrorHandlerFunc}), mux)
	api.RegisterStatic(mux)
	api.RegisterMetrics(mux)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.ApiPort),
		Handler: mux,
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.WithField("port", cfg.ApiPort).Info("server started")
		if err := server.ListenAndServe(); err != nil {
			log.WithField("error", err).Error("starting http server")
		}
	}()

	<-quit
	log.Info("Shutting down")
}

func registerMetrics() {
	prometheus.MustRegister(metrics.TotalRequests)
	prometheus.MustRegister(metrics.HttpDuration)
	prometheus.MustRegister(metrics.ResponseStatus)
}
