// Package autoban owns immutable policy inputs, decisions, and shared ban state.
// It deliberately has no dependency on Coraza transactions or HAProxy writers.
package autoban

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Scope identifies which shared state a policy or record belongs to.
type Scope string

const (
	ScopeApplication Scope = "application"
	ScopeGlobal      Scope = "global"
)

// Mode is the enforcement posture of a request.
type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

// Action is the effective or hypothetical policy result.
type Action string

const (
	ActionNone     Action = "none"
	ActionBan      Action = "ban"
	ActionThrottle Action = "throttle"
)

// Reason is a bounded degradation or rejection cause. It never carries
// credentials, raw request content, or arbitrary error text.
type Reason string

const (
	ReasonNone             Reason = ""
	ReasonInvalidIdentity  Reason = "invalid_identity"
	ReasonTimeout          Reason = "timeout"
	ReasonConnection       Reason = "connection"
	ReasonReadOnly         Reason = "read_only"
	ReasonOOM              Reason = "oom"
	ReasonWrongType        Reason = "wrong_type"
	ReasonMalformedReply   Reason = "malformed_reply"
	ReasonSaturated        Reason = "saturated"
	ReasonBudgetExhausted  Reason = "budget_exhausted"
	ReasonStaleGeneration  Reason = "stale_generation"
	ReasonExpiredAdmission Reason = "expired_admission"
	ReasonClockRegression  Reason = "clock_regression"
	ReasonEvidenceOverflow Reason = "evidence_overflow"
	ReasonFieldLimit       Reason = "field_limit"
	ReasonEntropyFailure   Reason = "entropy_failure"
)

// RequestID is a 128-bit internal identity, independent of HTTP/Coraza IDs.
type RequestID [16]byte

// Subject is the canonical identity used for shared state.
type Subject struct {
	Application string
	IP          netip.Addr
	Mode        Mode
}

// RequestMeta is copied request metadata kept outside Store commands.
type RequestMeta struct {
	Subject   Subject
	RequestID RequestID
	Method    string
	RawPath   string
}

// PolicyRef identifies a compiled policy and its semantic fingerprint.
type PolicyRef struct {
	ID          string
	Fingerprint string
	Scope       Scope
}

// MatchSpec carries only the selected policy parameters to the store.
type MatchSpec struct {
	Ref       PolicyRef
	Threshold int
	WindowMS  int64
	BanForMS  int64
}

// RateSpec carries only the selected rate parameters to the store.
type RateSpec struct {
	Ref      PolicyRef
	Requests int64
	PeriodMS int64
	Burst    int64
}

// Admission is an immutable token captured at Begin. Its config field is
// private: callers cannot alter the policy snapshot an operation will use.
type Admission struct {
	config               Config
	Meta                 RequestMeta
	RedisAdmittedAtMS    int64
	LocalAdmittedAt      time.Time
	Fences               map[Scope]string
	SuppressedUntilMS    map[Scope]int64
	RemainingStoreBudget time.Duration
	Usable               bool
	ShadowStopped        bool
}

// RuleMatch is immutable scalar metadata copied from a WAF match.
type RuleMatch struct {
	ID       int
	Phase    int
	Tags     []string
	Severity string
}

// Evidence is the bounded, copied evidence for one aggregated observation.
type Evidence struct {
	Matches         []RuleMatch
	AnomalyScore    *int64
	WAFInterrupted  bool
	InspectionError bool
}

// BanRecord is a shared, fixed-expiry ban.
type BanRecord struct {
	Subject             Subject
	Ref                 PolicyRef
	Revision            string
	QualifyingPolicyIDs []string
	TriggerRequestID    RequestID
	Count               int
	WindowMS            int64
	CreatedAtMS         int64
	ExpiresAtMS         int64
}

// Decision is the policy result for one request.
type Decision struct {
	Action            Action
	WouldAction       Action
	Scope             Scope
	PolicyID          string
	ExpiresAtMS       int64
	RetryAfterSeconds int64
	Ban               *BanRecord
	Degraded          bool
	Reason            Reason
}

// BeginCommand is the admission store command.
type BeginCommand struct {
	Subject   Subject
	RequestID RequestID
	Rates     []RateSpec
}

// BeginResult is the admission store result.
type BeginResult struct {
	NowMS             int64
	Fences            map[Scope]string
	SuppressedUntilMS map[Scope]int64
	Bans              []BanRecord
	ThrottlePolicyID  string
	RetryAfterSeconds int64
}

// ObserveCommand is the evidence store command.
type ObserveCommand struct {
	Subject           Subject
	RequestID         RequestID
	Revision          string
	AdmittedAtMS      int64
	Fences            map[Scope]string
	SuppressedUntilMS map[Scope]int64
	Policies          []MatchSpec
}

// ObserveResult is the evidence store result.
type ObserveResult struct {
	NowMS    int64
	Bans     []BanRecord
	Rejected map[Scope]Reason
}

// UnbanRequest is an explicit administrative reset.
type UnbanRequest struct {
	Mode        Mode
	Scope       Scope
	Application string
	IP          netip.Addr
	OperationID string
	SuppressFor time.Duration
	Reason      string
}

// UnbanResult is the timestamped, replayable reset result.
type UnbanResult struct {
	StateExisted                      bool
	Replayed                          bool
	RemainingApplicationBansEvaluated bool
	Nonce                             string
	ResetAtMS                         int64
	SuppressedUntilMS                 int64
	OtherBan                          *BanRecord
}

// InspectRequest requests both scopes for a subject.
type InspectRequest struct {
	Subject Subject
}

// InspectResult reports both scopes for a subject.
type InspectResult struct {
	Bans              []BanRecord
	SuppressedUntilMS map[Scope]int64
}

// ListRequest requests a bounded page of active bans.
type ListRequest struct {
	Mode        Mode
	Scope       Scope
	Application string
	Cursor      string
	Limit       int
}

// ListResult is a bounded page of active bans.
type ListResult struct {
	Bans     []BanRecord
	Cursor   string
	Examined int
}

// StoreError is a typed dependency failure. It never exposes secrets.
type StoreError struct {
	Reason    Reason
	Uncertain bool
	Err       error
}

func (e *StoreError) Error() string {
	if e.Reason == ReasonNone {
		return "autoban store error"
	}
	return "autoban store error: " + string(e.Reason)
}

func (e *StoreError) Unwrap() error { return e.Err }

// Administrative sentinel errors. Task 7 maps these to HTTP status codes;
// they are never request-policy degradation.
var (
	ErrOperationConflict = errors.New("autoban operation conflict")
	ErrCursorExpired     = errors.New("autoban cursor expired")
	ErrCursorMismatch    = errors.New("autoban cursor mismatch")
	ErrCursorCapacity    = errors.New("autoban cursor capacity")
	ErrScanBatchTooLarge = errors.New("autoban scan batch too large")
)

// Store abstracts all policy state operations so unit tests need no Redis.
type Store interface {
	Begin(context.Context, BeginCommand) (BeginResult, error)
	Observe(context.Context, ObserveCommand) (ObserveResult, error)
	Unban(context.Context, UnbanRequest) (UnbanResult, error)
	Inspect(context.Context, InspectRequest) (InspectResult, error)
	List(context.Context, ListRequest) (ListResult, error)
}
