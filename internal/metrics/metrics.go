package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// TotalRequests - CounterVec to store the total number of requests per path
var TotalRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total_per_path",
		Help: "Number of get requests per path",
	},
	[]string{"path"},
)

// ResponseStatus - CounterVec to store the status of the response
var ResponseStatus = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_response_status",
		Help: "Status of HTTP response",
	},
	[]string{"status"},
)

// HttpDuration - HistogramVec to store the duration of the HTTP requests per path
var HttpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: "http_response_time_seconds_per_path",
	Help: "Duration of HTTP requests per path",
}, []string{"path"})

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// PrometheusTotalRequestsMiddleware - Middleware to record metrics for the API
func PrometheusTotalRequestsMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		path := r.URL.Path
		if mustBeExcluded(path) {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		timer := prometheus.NewTimer(HttpDuration.WithLabelValues(path))
		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)

		statusCode := rw.statusCode
		ResponseStatus.WithLabelValues(strconv.Itoa(statusCode)).Inc()
		TotalRequests.WithLabelValues(path).Inc()

		timer.ObserveDuration()
	}
	return http.HandlerFunc(fn)
}

func mustBeExcluded(path string) bool {
	mustBe := false
	if path == "" || path == "/static/docs/api/api.yaml" || path == "/metrics" {
		mustBe = true
	}
	return mustBe
}
