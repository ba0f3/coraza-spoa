package autoban

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// auditSampler bounds repeated decision and error logs while leaving
// transitions (activation, unban, observed expiry, degradation) explainable.
var (
	auditSampler     = zerolog.BurstSampler{Burst: 20, Period: time.Minute}
	degradationAudit sync.Map
)

// AuditBan emits a bounded record with canonical identity and policy metadata.
// Request bodies, credentials, cookies, and raw match data are never included.
func AuditBan(logger zerolog.Logger, ban BanRecord, requestID RequestID, transactionID string) {
	sampled := logger.Sample(&auditSampler)
	ev := sampled.Info().
		Str("event", "autoban.ban").
		Str("application", ban.Subject.Application).
		Str("ip", ban.Subject.IP.String()).
		Str("mode", string(ban.Subject.Mode)).
		Str("scope", string(ban.Ref.Scope)).
		Str("policy", ban.Ref.ID).
		Str("fingerprint", ban.Ref.Fingerprint).
		Str("request_id", hex.EncodeToString(requestID[:])).
		Int("count", ban.Count).
		Int64("window_ms", ban.WindowMS).
		Int64("expires_at_ms", ban.ExpiresAtMS)
	if transactionID != "" {
		ev.Str("transaction_id", transactionID)
	}
	ev.Msg("ban activated")
}

// AuditDegradation logs a degradation transition once per reason, then samples
// repeated occurrences. It never logs credentials, raw errors, or request data.
func AuditDegradation(logger zerolog.Logger, application string, reason Reason) {
	if _, loaded := degradationAudit.LoadOrStore(reason, struct{}{}); !loaded {
		logger.Warn().
			Str("event", "autoban.degraded").
			Str("application", application).
			Str("reason", string(reason)).
			Msg("policy dependency degraded")
	}
}
