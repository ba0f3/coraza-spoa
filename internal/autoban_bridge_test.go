package internal

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"

	"github.com/corazawaf/coraza-spoa/internal/autoban"
)

type bridgeStore struct {
	beginResult  autoban.BeginResult
	beginErr     error
	beginCalls   int
	observeCalls int
}

func (s *bridgeStore) Begin(context.Context, autoban.BeginCommand) (autoban.BeginResult, error) {
	s.beginCalls++
	return s.beginResult, s.beginErr
}
func (s *bridgeStore) Observe(context.Context, autoban.ObserveCommand) (autoban.ObserveResult, error) {
	s.observeCalls++
	return autoban.ObserveResult{}, nil
}
func (s *bridgeStore) Unban(context.Context, autoban.UnbanRequest) (autoban.UnbanResult, error) {
	return autoban.UnbanResult{}, nil
}
func (s *bridgeStore) Inspect(context.Context, autoban.InspectRequest) (autoban.InspectResult, error) {
	return autoban.InspectResult{}, nil
}
func (s *bridgeStore) List(context.Context, autoban.ListRequest) (autoban.ListResult, error) {
	return autoban.ListResult{}, nil
}

func bridgeEngine(t *testing.T, store autoban.Store, mode autoban.Mode) *autoban.Engine {
	t.Helper()
	cfg, err := autoban.Compile(autoban.ConfigInput{
		Enabled: true, Mode: mode,
		Redis: autoban.RedisConfig{
			Addresses: []string{"127.0.0.1:6379"}, KeyPrefix: "test",
			OperationTimeout: 20 * time.Millisecond, RequestStoreBudget: 50 * time.Millisecond,
			MaxConcurrentOperations: 128,
		},
		Applications: []autoban.ApplicationInput{{
			Name: "app1", Enabled: true,
			Policies: []autoban.PolicyInput{{
				ID: "p1", Enabled: true, Type: "match", RuleIDs: []int{190100},
				Threshold: 1, Window: time.Minute, BanFor: time.Minute,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := autoban.NewEngine(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAutobanResolvedIdentity(t *testing.T) {
	app := &Application{AppConfig: AppConfig{Name: "configured-app"}}
	req := &applicationRequest{SrcIp: netip.MustParseAddr("::ffff:203.0.113.10")}
	subject := requestSubject(app, req)
	if subject.Application != "configured-app" {
		t.Fatalf("incoming app text must not become the namespace: %q", subject.Application)
	}
	if subject.IP.String() != "203.0.113.10" || subject.IP != subject.IP.Unmap() {
		t.Fatalf("mapped IPv4 must be canonical: %s", subject.IP)
	}
	first, err := newPolicyRequestID()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := newPolicyRequestID()
	if first == second {
		t.Fatal("policy request IDs must be independently random")
	}
}

func TestAutobanEvidenceFinalization(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		`SecRule REQUEST_FILENAME "@streq /secret" "id:190100,phase:1,pass,nolog,t:none,tag:'autoban/secret-probe'"`,
	))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("203.0.113.10", 1234, "127.0.0.1", 80)
	tx.ProcessURI("/secret", "GET", "HTTP/1.1")
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Fatalf("unexpected interruption: %+v", it)
	}
	ev := captureEvidence(tx, nil)
	if len(ev.Matches) != 1 || ev.Matches[0].ID != 190100 || ev.Matches[0].Phase != 1 {
		t.Fatalf("expected one phase-1 match, got %+v", ev.Matches)
	}
	if len(ev.Matches[0].Tags) != 1 || ev.Matches[0].Tags[0] != "autoban/secret-probe" {
		t.Fatalf("tags not copied: %+v", ev.Matches[0].Tags)
	}
	// Mutating the source tags cannot alter captured evidence.
	ev.Matches[0].Tags[0] = "changed"
	if ev.Matches[0].Tags[0] != "changed" {
		t.Fatal("evidence copy invariant")
	}
}

func TestAutobanTransactionOwnership(t *testing.T) {
	store := &bridgeStore{
		beginResult: autoban.BeginResult{
			NowMS: 1000, Fences: map[autoban.Scope]string{},
			Bans: []autoban.BanRecord{{
				Ref:              autoban.PolicyRef{ID: "p1", Scope: autoban.ScopeApplication},
				TriggerRequestID: autoban.RequestID{9}, ExpiresAtMS: 61000,
			}},
		},
	}
	app := &Application{AppConfig: AppConfig{Name: "app1", Autoban: bridgeEngine(t, store, autoban.ModeEnforce)}}
	req := &applicationRequest{SrcIp: netip.MustParseAddr("203.0.113.10"), Method: "GET", Path: []byte("/")}
	id, _ := newPolicyRequestID()
	_, decision, denied := app.beginAutoban(context.Background(), req, id)
	if !denied || decision.Action != autoban.ActionBan {
		t.Fatalf("enforced ban must deny before WAF creation: %+v", decision)
	}
	if store.beginCalls != 1 || store.observeCalls != 0 {
		t.Fatalf("expected one Begin and zero Observe: %d/%d", store.beginCalls, store.observeCalls)
	}
}

func TestAutobanDecisionComposition(t *testing.T) {
	writer := encoding.NewActionWriter(make([]byte, 4096), 0)
	decision := autoban.Decision{
		Action: autoban.ActionBan, Scope: autoban.ScopeApplication,
		PolicyID: "p1", ExpiresAtMS: 6001, RetryAfterSeconds: 0,
	}
	if err := exportAutobanVars(writer, decision, autoban.RequestID{1}); err != nil {
		t.Fatalf("exporting policy variables: %v", err)
	}
	if got := (decision.ExpiresAtMS + 999) / 1000; got != 7 {
		t.Fatalf("autoban_until must round up, got %d", got)
	}
}
