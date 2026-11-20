package internal

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"

	"github.com/corazawaf/coraza-spoa/internal/autoban"
)

// cacheForResponse decides whether a transaction stays owned by the response
// correlation cache. A local policy denial must close the transaction instead
// of leaving an orphan waiting for a coraza-res that will never arrive.
func cacheForResponse(wafErr error, req *applicationRequest, decision autoban.Decision) bool {
	if decision.Action != autoban.ActionNone && decision.Action != "" {
		return false
	}
	var interruption ErrInterrupted
	return wafErr == nil || (req.DetectOnly && errors.As(wafErr, &interruption))
}

// newPolicyRequestID generates the independent 128-bit policy identity.
func newPolicyRequestID() (autoban.RequestID, error) {
	var id autoban.RequestID
	if _, err := rand.Read(id[:]); err != nil {
		return autoban.RequestID{}, err
	}
	return id, nil
}

// requestSubject builds the canonical subject from already-resolved inputs.
// a.Name is the configured application resolved by Agent.HandleSPOE, never the
// incoming app text; the address is canonicalized with Unmap.
func requestSubject(a *Application, req *applicationRequest) autoban.Subject {
	ip := req.SrcIp
	if ip.IsValid() {
		ip = ip.Unmap()
	}
	return autoban.Subject{Application: a.Name, IP: ip}
}

// beginAutoban performs admission before any Coraza transaction is created.
// It reports whether a policy denial has fully handled the request.
func (a *Application) beginAutoban(ctx context.Context, req *applicationRequest, id autoban.RequestID) (autoban.Admission, autoban.Decision, bool) {
	if a.Autoban == nil {
		return autoban.Admission{}, autoban.Decision{Action: autoban.ActionNone}, false
	}
	meta := autoban.RequestMeta{
		Subject:   requestSubject(a, req),
		RequestID: id,
		Method:    req.Method,
		RawPath:   string(req.Path),
	}
	adm, decision := a.Autoban.Begin(ctx, meta)
	autoban.RecordDecision(a.Name, meta.Subject.Mode, decision)
	if decision.Degraded {
		autoban.AuditDegradation(a.Logger, a.Name, decision.Reason)
	}
	if decision.Degraded || decision.Action == autoban.ActionNone {
		return adm, decision, false
	}
	// An enforced ban or throttle denies before WAF creation.
	return adm, decision, true
}

// captureEvidence copies immutable scalar metadata while the transaction is
// still owned by the handler. Borrowed buffers and variables are never kept.
func captureEvidence(tx types.Transaction, wafErr error) autoban.Evidence {
	ev := autoban.Evidence{}
	var interruption ErrInterrupted
	if wafErr != nil {
		if errors.As(wafErr, &interruption) {
			ev.WAFInterrupted = true
		} else {
			ev.InspectionError = true
		}
	}
	if tx == nil {
		return ev
	}
	matched := tx.MatchedRules()
	if len(matched) > 256 {
		ev.InspectionError = true
		return ev
	}
	for _, mr := range matched {
		phase := int(mr.Rule().Phase())
		if phase != 1 && phase != 2 {
			continue
		}
		rule := mr.Rule()
		ev.Matches = append(ev.Matches, autoban.RuleMatch{
			ID:       rule.ID(),
			Phase:    phase,
			Tags:     append([]string(nil), rule.Tags()...),
			Severity: rule.Severity().String(),
		})
	}
	if state, ok := tx.(plugintypes.TransactionState); ok {
		values := state.Variables().TX().Get("anomaly_score")
		if len(values) != 0 {
			if score, err := strconv.ParseInt(values[0], 10, 64); err == nil {
				ev.AnomalyScore = &score
			}
		}
	}
	return ev
}

// finishAutoban captures evidence and performs at most one aggregated Observe.
// WAF outcomes are preserved; policy results travel in separate variables.
func (a *Application) finishAutoban(ctx context.Context, adm autoban.Admission, tx types.Transaction, wafErr error, id autoban.RequestID) autoban.Decision {
	if a.Autoban == nil || !adm.Usable || adm.ShadowStopped {
		return autoban.Decision{Action: autoban.ActionNone}
	}
	evidence := captureEvidence(tx, wafErr)
	decision := a.Autoban.Observe(ctx, adm, evidence)
	mode := adm.Meta.Subject.Mode
	autoban.RecordDecision(a.Name, mode, decision)
	if decision.Ban != nil {
		autoban.AuditBan(a.Logger, *decision.Ban, adm.Meta.RequestID, "")
	}
	if decision.Degraded {
		autoban.AuditDegradation(a.Logger, a.Name, decision.Reason)
	}
	return decision
}

// exportAutobanVars initializes every transaction-scoped policy variable.
func exportAutobanVars(writer *encoding.ActionWriter, d autoban.Decision, id autoban.RequestID) error {
	action, would, scope, policy := string(d.Action), string(d.WouldAction), string(d.Scope), d.PolicyID
	if d.Action == "" {
		action = string(autoban.ActionNone)
	}
	if d.WouldAction == "" {
		would = string(autoban.ActionNone)
	}
	until := int64(0)
	if d.ExpiresAtMS > 0 {
		until = (d.ExpiresAtMS + 999) / 1000
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{"autoban_action", action},
		{"autoban_would_action", would},
		{"autoban_policy", policy},
		{"autoban_scope", scope},
		{"autoban_retry_after", strconv.FormatInt(d.RetryAfterSeconds, 10)},
		{"autoban_request_id", requestIDString(id)},
	} {
		if err := writer.SetString(encoding.VarScopeTransaction, item.name, item.value); err != nil {
			return err
		}
	}
	if err := writer.SetInt64(encoding.VarScopeTransaction, "autoban_until", until); err != nil {
		return err
	}
	return writer.SetBool(encoding.VarScopeTransaction, "policy_degraded", d.Degraded)
}

func requestIDString(id autoban.RequestID) string {
	const digits = "0123456789abcdef"
	b := make([]byte, len(id)*2)
	for i, v := range id {
		b[i*2], b[i*2+1] = digits[v>>4], digits[v&0x0f]
	}
	return string(b)
}

// parsedIP is used by tests to assert canonical identity without netip APIs.
func parsedIP(s string) netip.Addr { return netip.MustParseAddr(s) }
