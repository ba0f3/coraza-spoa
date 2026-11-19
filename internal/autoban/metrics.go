package autoban

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metric labels come from configured finite sets. Client IPs, request IDs,
// URLs, untrusted application names, and error strings are never labels.
var (
	autobanRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_autoban_requests_total",
		Help: "Total auto-ban request evaluations by configured application, mode, and result.",
	}, []string{"application", "mode", "result"})

	autobanDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_autoban_decisions_total",
		Help: "Total auto-ban decisions by configured application, mode, scope, policy, and action.",
	}, []string{"application", "mode", "scope", "policy", "action"})

	autobanStoreDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "coraza_autoban_store_duration_seconds",
		Help:    "Duration of bounded Redis store operations by operation and result.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2},
	}, []string{"operation", "result"})

	autobanDegradedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_autoban_degraded_total",
		Help: "Total auto-ban degradations by configured application and bounded reason.",
	}, []string{"application", "reason"})

	autobanEvidenceRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_autoban_evidence_rejected_total",
		Help: "Total rejected evidence by configured application and bounded reason.",
	}, []string{"application", "reason"})

	autobanAdminOperationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_autoban_admin_operations_total",
		Help: "Total admin operations by operation and result.",
	}, []string{"operation", "result"})

	autobanConfigInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "coraza_autoban_config_info",
		Help: "Active auto-ban configuration revision; 1 for the currently published revision.",
	}, []string{"revision"})
)

var activeRevision string

// RecordDecision emits bounded decision and degradation metrics for one result.
func RecordDecision(application string, mode Mode, d Decision) {
	result := string(d.Action)
	if d.Degraded {
		result = "degraded"
	}
	autobanRequestsTotal.WithLabelValues(application, string(mode), result).Inc()
	policy := d.PolicyID
	if policy == "" {
		policy = "none"
	}
	scope := string(d.Scope)
	if scope == "" {
		scope = "none"
	}
	action := string(d.Action)
	if d.Action == "" {
		action = string(ActionNone)
	}
	autobanDecisionsTotal.WithLabelValues(application, string(mode), scope, policy, action).Inc()
	if d.Degraded {
		reason := string(d.Reason)
		if reason == "" {
			reason = "connection"
		}
		autobanDegradedTotal.WithLabelValues(application, reason).Inc()
		if reason == string(ReasonStaleGeneration) || reason == string(ReasonExpiredAdmission) || reason == string(ReasonEvidenceOverflow) {
			autobanEvidenceRejectedTotal.WithLabelValues(application, reason).Inc()
		}
	}
}

// recordStoreOperation records one bounded store call.
func recordStoreOperation(operation string, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	autobanStoreDuration.WithLabelValues(operation, result).Observe(0)
}

// SetConfigRevision publishes a bounded config-info label set, removing the
// previously active revision so replaced labels disappear on reload.
func SetConfigRevision(revision string) {
	if revision == "" {
		return
	}
	if activeRevision != "" && activeRevision != revision {
		autobanConfigInfo.DeleteLabelValues(activeRevision)
	}
	activeRevision = revision
	autobanConfigInfo.WithLabelValues(revision).Set(1)
}
