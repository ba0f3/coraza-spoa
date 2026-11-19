package autoban

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed lua/*.lua
var luaFiles embed.FS

const luaPrelude = `
-- cjson is provided as a global by Redis's Lua sandbox.
local function now_ms()
  local t = redis.call("TIME")
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
local function read_state(key, now)
  local out = {}
  local raw = redis.call("HGETALL", key)
  for i = 1, #raw, 2 do
    local field, value = raw[i], raw[i + 1]
    local ok, obj = pcall(cjson.decode, value)
    if ok and type(obj) == "table" and obj.exp and tonumber(obj.exp) <= now then
      -- expired field: prune
    else
      out[field] = value
    end
  end
  return out
end
`

func loadScript(name string) string {
	b, err := luaFiles.ReadFile("lua/" + name)
	if err != nil {
		panic(err)
	}
	return luaPrelude + string(b)
}

var (
	beginScript   = loadScript("begin.lua")
	observeScript = loadScript("observe.lua")
	unbanScript   = loadScript("unban.lua")
	inspectScript = loadScript("inspect.lua")
	listScript    = loadScript("list.lua")
)

type luaBan struct {
	Scope       string   `json:"scope"`
	PolicyID    string   `json:"policy_id"`
	Fingerprint string   `json:"fingerprint"`
	Revision    string   `json:"revision"`
	Qualifying  []string `json:"qualifying"`
	Trigger     string   `json:"trigger"`
	Count       int      `json:"count"`
	WindowMS    int64    `json:"window_ms"`
	CreatedAtMS int64    `json:"created_at_ms"`
	ExpiresAtMS int64    `json:"expires_at_ms"`
}

type luaErrorEnvelope struct {
	Error string `json:"error"`
}

func (e luaErrorEnvelope) asError() error {
	if e.Error == "" {
		return nil
	}
	switch e.Error {
	case "conflict":
		return ErrOperationConflict
	case "field_limit":
		return &StoreError{Reason: ReasonFieldLimit, Uncertain: false}
	case "clock_regression":
		return &StoreError{Reason: ReasonClockRegression, Uncertain: false}
	case "expired_admission":
		return &StoreError{Reason: ReasonExpiredAdmission, Uncertain: false}
	case "stale_generation":
		return &StoreError{Reason: ReasonStaleGeneration, Uncertain: false}
	default:
		return &StoreError{Reason: ReasonMalformedReply}
	}
}

func banFromLua(b luaBan) BanRecord {
	subject := Subject{Application: b.Scope, Mode: Mode("")}
	return BanRecord{
		Subject:             subject,
		Ref:                 PolicyRef{ID: b.PolicyID, Fingerprint: b.Fingerprint, Scope: Scope(b.Scope)},
		Revision:            b.Revision,
		QualifyingPolicyIDs: b.Qualifying,
		TriggerRequestID:    requestIDFromHex(b.Trigger),
		Count:               b.Count,
		WindowMS:            b.WindowMS,
		CreatedAtMS:         b.CreatedAtMS,
		ExpiresAtMS:         b.ExpiresAtMS,
	}
}

func requestIDFromHex(s string) RequestID {
	var id RequestID
	b, err := hex.DecodeString(s)
	if err == nil && len(b) == len(id) {
		copy(id[:], b)
	}
	return id
}

func requestIDHex(id RequestID) string { return hex.EncodeToString(id[:]) }

type luaBegin struct {
	luaErrorEnvelope
	NowMS             int64    `json:"now_ms"`
	Bans              []luaBan `json:"bans"`
	ThrottlePolicyID  string   `json:"throttle_policy_id"`
	RetryAfterSeconds int64    `json:"retry_after_seconds"`
	Fences            []struct {
		Scope string `json:"scope"`
		Nonce string `json:"nonce"`
	} `json:"fences"`
	Suppressed []struct {
		Scope   string `json:"scope"`
		UntilMS int64  `json:"until_ms"`
	} `json:"suppressed"`
}

func parseBeginResult(raw interface{}) (BeginResult, error) {
	var v luaBegin
	if err := decodeLua(raw, &v); err != nil {
		return BeginResult{}, err
	}
	if err := v.asError(); err != nil {
		return BeginResult{}, err
	}
	out := BeginResult{
		NowMS: v.NowMS, ThrottlePolicyID: v.ThrottlePolicyID,
		RetryAfterSeconds: v.RetryAfterSeconds,
		Fences:            map[Scope]string{}, SuppressedUntilMS: map[Scope]int64{},
	}
	for _, f := range v.Fences {
		if f.Scope != "" {
			out.Fences[Scope(f.Scope)] = f.Nonce
		}
	}
	for _, s := range v.Suppressed {
		if s.Scope != "" {
			out.SuppressedUntilMS[Scope(s.Scope)] = s.UntilMS
		}
	}
	for _, b := range v.Bans {
		out.Bans = append(out.Bans, banFromLua(b))
	}
	return out, nil
}

type luaObserve struct {
	luaErrorEnvelope
	NowMS    int64    `json:"now_ms"`
	Bans     []luaBan `json:"bans"`
	Rejected []struct {
		Scope  string `json:"scope"`
		Reason string `json:"reason"`
	} `json:"rejected"`
}

func parseObserveResult(raw interface{}) (ObserveResult, error) {
	var v luaObserve
	if err := decodeLua(raw, &v); err != nil {
		return ObserveResult{}, err
	}
	if err := v.asError(); err != nil {
		return ObserveResult{}, err
	}
	out := ObserveResult{NowMS: v.NowMS, Rejected: map[Scope]Reason{}}
	for _, r := range v.Rejected {
		if r.Scope != "" {
			out.Rejected[Scope(r.Scope)] = Reason(r.Reason)
		}
	}
	for _, b := range v.Bans {
		out.Bans = append(out.Bans, banFromLua(b))
	}
	return out, nil
}

type luaUnban struct {
	luaErrorEnvelope
	StateExisted                      bool    `json:"state_existed"`
	Replayed                          bool    `json:"replayed"`
	RemainingApplicationBansEvaluated bool    `json:"remaining_application_bans_evaluated"`
	Nonce                             string  `json:"nonce"`
	ResetAtMS                         int64   `json:"reset_at_ms"`
	SuppressedUntilMS                 int64   `json:"suppressed_until_ms"`
	OtherBan                          *luaBan `json:"other_ban"`
}

func parseUnbanResult(raw interface{}) (UnbanResult, error) {
	var v luaUnban
	if err := decodeLua(raw, &v); err != nil {
		return UnbanResult{}, err
	}
	if err := v.asError(); err != nil {
		return UnbanResult{}, err
	}
	out := UnbanResult{
		StateExisted: v.StateExisted, Replayed: v.Replayed,
		RemainingApplicationBansEvaluated: v.RemainingApplicationBansEvaluated,
		Nonce:                             v.Nonce, ResetAtMS: v.ResetAtMS, SuppressedUntilMS: v.SuppressedUntilMS,
	}
	if v.OtherBan != nil {
		ban := banFromLua(*v.OtherBan)
		out.OtherBan = &ban
	}
	return out, nil
}

type luaInspect struct {
	luaErrorEnvelope
	NowMS      int64    `json:"now_ms"`
	Bans       []luaBan `json:"bans"`
	Suppressed []struct {
		Scope   string `json:"scope"`
		UntilMS int64  `json:"until_ms"`
	} `json:"suppressed"`
}

func parseInspectResult(raw interface{}) (InspectResult, error) {
	var v luaInspect
	if err := decodeLua(raw, &v); err != nil {
		return InspectResult{}, err
	}
	if err := v.asError(); err != nil {
		return InspectResult{}, err
	}
	out := InspectResult{Bans: []BanRecord{}, SuppressedUntilMS: map[Scope]int64{}}
	for _, b := range v.Bans {
		out.Bans = append(out.Bans, banFromLua(b))
	}
	for _, s := range v.Suppressed {
		if s.Scope != "" {
			out.SuppressedUntilMS[Scope(s.Scope)] = s.UntilMS
		}
	}
	return out, nil
}

type luaList struct {
	luaErrorEnvelope
	Cursor   string   `json:"cursor"`
	Examined int      `json:"examined"`
	Bans     []luaBan `json:"bans"`
}

func parseListResult(raw interface{}) (ListResult, error) {
	var v luaList
	if err := decodeLua(raw, &v); err != nil {
		return ListResult{}, err
	}
	if err := v.asError(); err != nil {
		return ListResult{}, err
	}
	out := ListResult{Cursor: v.Cursor, Examined: v.Examined, Bans: []BanRecord{}}
	for _, b := range v.Bans {
		out.Bans = append(out.Bans, banFromLua(b))
	}
	return out, nil
}

func decodeLua(raw interface{}, out interface{}) error {
	var text string
	switch v := raw.(type) {
	case string:
		text = v
	case []byte:
		text = string(v)
	case nil:
		return &StoreError{Reason: ReasonMalformedReply}
	default:
		return fmt.Errorf("autoban: unexpected Lua reply type %T", raw)
	}
	if strings.TrimSpace(text) == "" {
		return &StoreError{Reason: ReasonMalformedReply}
	}

	// Redis cjson encodes empty Lua tables as JSON objects; normalize them to
	// arrays for the slice fields in our reply structs.
	text = strings.ReplaceAll(text, "{}", "[]")
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return &StoreError{Reason: ReasonMalformedReply, Err: err}
	}
	return nil
}
