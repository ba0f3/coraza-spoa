package autoban

import (
	"context"
	"errors"
	"time"
)

const (
	maxAdmissionAge        = 30 * time.Second
	maxSelectedRuleRecords = 256
)

// Engine applies an immutable policy snapshot to trusted request evidence.
type Engine struct {
	config  Config
	store   Store
	now     func() time.Time
	tracker func() func()
}

// SetActivityTracker installs a runtime hook that bounds in-flight policy
// operations during shutdown. It must be set before the engine is published.
func (e *Engine) SetActivityTracker(tracker func() func()) { e.tracker = tracker }

// Track marks one policy operation as active. Without a runtime tracker this
// is a no-op, so unit tests and disabled runtimes stay unaffected.
func (e *Engine) Track() func() {
	if e == nil || e.tracker == nil {
		return func() {}
	}
	return e.tracker()
}

// NewEngine captures a deep copy of config and owns no request resources.
func NewEngine(config Config, store Store) (*Engine, error) {
	return newEngineWithClock(config, store, time.Now)
}

func newEngineWithClock(config Config, store Store, now func() time.Time) (*Engine, error) {
	if store == nil {
		return nil, errors.New("autoban: nil store")
	}
	if now == nil {
		now = time.Now
	}
	return &Engine{config: cloneConfig(config), store: store, now: now}, nil
}

// Begin resolves identity and rates, then performs one bounded admission call.
func (e *Engine) Begin(ctx context.Context, meta RequestMeta) (Admission, Decision) {
	adm := Admission{
		Meta:                 meta,
		RemainingStoreBudget: e.config.limits.requestBudget,
	}

	app, ok := e.config.eligibleApp(meta.Subject.Application)
	if !ok {
		return adm, Decision{Action: ActionNone}
	}
	if !meta.Subject.IP.IsValid() {
		return adm, Decision{Action: ActionNone, Degraded: true, Reason: ReasonInvalidIdentity}
	}
	if isExempt(app, meta.Subject.IP) {
		return adm, Decision{Action: ActionNone}
	}

	mode := meta.Subject.Mode
	if mode == "" {
		mode = e.config.effectiveMode(app)
	}
	subject := meta.Subject
	subject.IP = subject.IP.Unmap()
	subject.Mode = mode
	meta.Subject = subject
	adm.Meta = meta

	if e.config.limits.requestBudget <= 0 {
		return adm, Decision{Action: ActionNone, Degraded: true, Reason: ReasonBudgetExhausted}
	}

	rates := selectRates(app, meta)
	admitTime := e.now()
	callCtx, cancel := e.contextWithBudget(ctx, e.config.limits.requestBudget)
	res, err := e.store.Begin(callCtx, BeginCommand{
		Subject:   subject,
		RequestID: meta.RequestID,
		Rates:     rates,
	})
	elapsed := e.now().Sub(admitTime)
	cancel()
	if elapsed < 0 {
		elapsed = 0
	}
	adm.RemainingStoreBudget -= elapsed
	if adm.RemainingStoreBudget < 0 {
		adm.RemainingStoreBudget = 0
	}
	if err != nil {
		return adm, degradedDecision(err)
	}

	adm.Usable = true
	adm.RedisAdmittedAtMS = res.NowMS
	adm.LocalAdmittedAt = admitTime
	adm.Fences = cloneFences(res.Fences)
	adm.SuppressedUntilMS = cloneSuppression(res.SuppressedUntilMS)

	d := Decision{Action: ActionNone}
	if b := pickBan(res.Bans, RequestID{}, false); b != nil {
		d = decisionFromBan(b, mode)
	} else if res.ThrottlePolicyID != "" || res.RetryAfterSeconds > 0 {
		d = Decision{
			Action:            ActionNone,
			Scope:             ScopeApplication,
			PolicyID:          res.ThrottlePolicyID,
			RetryAfterSeconds: res.RetryAfterSeconds,
		}
		if mode == ModeEnforce {
			d.Action = ActionThrottle
		} else {
			d.WouldAction = ActionThrottle
		}
	}
	if mode == ModeObserve && (d.WouldAction == ActionBan || d.WouldAction == ActionThrottle) {
		adm.ShadowStopped = true
	}
	return adm, d
}

// Observe performs at most one aggregated evidence call for an admitted request.
func (e *Engine) Observe(ctx context.Context, adm Admission, evidence Evidence) Decision {
	if !adm.Usable || adm.ShadowStopped {
		return Decision{Action: ActionNone}
	}
	if e.now().Sub(adm.LocalAdmittedAt) > maxAdmissionAge {
		return Decision{Action: ActionNone, Degraded: true, Reason: ReasonExpiredAdmission}
	}
	if adm.RemainingStoreBudget <= 0 {
		return Decision{Action: ActionNone, Degraded: true, Reason: ReasonBudgetExhausted}
	}
	if evidence.InspectionError || len(evidence.Matches) > maxSelectedRuleRecords {
		return Decision{Action: ActionNone, Degraded: true, Reason: ReasonEvidenceOverflow}
	}

	app, ok := e.config.eligibleApp(adm.Meta.Subject.Application)
	if !ok {
		return Decision{Action: ActionNone}
	}
	ev := cloneEvidence(evidence)
	policies := e.config.selectMatches(app, ev)
	if len(policies) == 0 {
		return Decision{Action: ActionNone}
	}

	callCtx, cancel := e.contextWithBudget(ctx, adm.RemainingStoreBudget)
	res, err := e.store.Observe(callCtx, ObserveCommand{
		Subject:           adm.Meta.Subject,
		RequestID:         adm.Meta.RequestID,
		Revision:          e.config.revision,
		AdmittedAtMS:      adm.RedisAdmittedAtMS,
		Fences:            cloneFences(adm.Fences),
		SuppressedUntilMS: cloneSuppression(adm.SuppressedUntilMS),
		Policies:          policies,
	})
	cancel()
	if err != nil {
		return degradedDecision(err)
	}

	d := Decision{Action: ActionNone}
	if b := pickBan(res.Bans, adm.Meta.RequestID, true); b != nil {
		d = decisionFromBan(b, adm.Meta.Subject.Mode)
	}
	if len(res.Rejected) > 0 && !d.Degraded {
		d.Degraded = true
		for scope, reason := range res.Rejected {
			if scope == ScopeGlobal {
				d.Reason = reason
				break
			}
			if d.Reason == ReasonNone {
				d.Reason = reason
			}
		}
	}
	return d
}

func (e *Engine) contextWithBudget(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	return context.WithTimeout(parent, budget)
}

func degradedDecision(err error) Decision {
	d := Decision{Action: ActionNone, Degraded: true}
	var se *StoreError
	if errors.As(err, &se) {
		d.Reason = se.Reason
	} else {
		d.Reason = ReasonConnection
	}
	return d
}

// pickBan prefers the global record when both scopes have an active ban.
func pickBan(bans []BanRecord, trigger RequestID, triggerOnly bool) *BanRecord {
	var appBan, globalBan *BanRecord
	for i := range bans {
		b := &bans[i]
		if triggerOnly && b.TriggerRequestID != trigger {
			continue
		}
		if b.Ref.Scope == ScopeGlobal {
			if globalBan == nil {
				globalBan = b
			}
		} else if appBan == nil {
			appBan = b
		}
	}
	if globalBan != nil {
		return globalBan
	}
	return appBan
}

func decisionFromBan(b *BanRecord, mode Mode) Decision {
	d := Decision{
		Action:      ActionNone,
		Scope:       b.Ref.Scope,
		PolicyID:    b.Ref.ID,
		ExpiresAtMS: b.ExpiresAtMS,
		Ban:         b,
	}
	if mode == ModeEnforce {
		d.Action = ActionBan
	} else {
		d.WouldAction = ActionBan
	}
	return d
}
