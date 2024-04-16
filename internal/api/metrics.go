package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegisterMetrics -  registers the static routes for the API.
func RegisterMetrics(mux *chi.Mux) {
	mux.Handle("/metrics", promhttp.Handler())
}
