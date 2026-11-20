-- OBSERVE: atomic evidence update and ban creation.
local function max_expiry(fields, floor_exp)
  local maxexp = floor_exp
  for _, raw in pairs(fields) do
    local ok, obj = pcall(cjson.decode, raw)
    if ok and type(obj) == "table" and obj.exp and tonumber(obj.exp) > maxexp then
      maxexp = tonumber(obj.exp)
    end
  end
  return maxexp
end

local mode, app, iphex, reqid, revision = ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5]
local admitted = tonumber(ARGV[6])
local captured_global, captured_app = ARGV[7], ARGV[8]
local nsuppressed = tonumber(ARGV[9])
local suppressed_until = {}
local idx = 10
for _ = 1, nsuppressed do
  suppressed_until[ARGV[idx]] = tonumber(ARGV[idx + 1])
  idx = idx + 2
end
local npolicies = tonumber(ARGV[idx])
idx = idx + 1
local now = now_ms()

local elapsed = now - admitted
if elapsed < 0 then return cjson.encode({ error = "clock_regression" }) end
if elapsed > 30000 then return cjson.encode({ error = "expired_admission" }) end

local scopes = { "global", "application" }
local captured = { [1] = captured_global, [2] = captured_app }
local state = { read_state(KEYS[1], now), read_state(KEYS[2], now) }
local rejected = {}

-- Fence validation before any mutation.
for i = 1, 2 do
  local nonce = redis.call("HGET", KEYS[2 + i], "nonce") or "none"
  local expires = tonumber(redis.call("HGET", KEYS[2 + i], "expires_at") or "0")
  if nonce ~= "none" and expires > now and captured[i] ~= nonce then
    rejected[#rejected + 1] = { scope = scopes[i], reason = "stale_generation" }
  end
end
if #rejected > 0 then return cjson.encode({ now_ms = now, bans = {}, rejected = rejected }) end

-- Preflight: validate both scopes before mutation.
local field_count = { 0, 0 }
for i = 1, 2 do
  for field, raw in pairs(state[i]) do
    field_count[i] = field_count[i] + 1
    if #raw > 65536 then return cjson.encode({ error = "field_limit" }) end
    local ok, obj = pcall(cjson.decode, raw)
    if ok and type(obj) == "table" and obj.t and tonumber(obj.t) > now then
      return cjson.encode({ error = "clock_regression" })
    end
  end
end

local policies = {}
for _ = 1, npolicies do
  local fp, id, scope, threshold, window, banfor = ARGV[idx], ARGV[idx + 1], ARGV[idx + 2], tonumber(ARGV[idx + 3]), tonumber(ARGV[idx + 4]), tonumber(ARGV[idx + 5])
  idx = idx + 6
  policies[#policies + 1] = { fp = fp, id = id, scope = scope, threshold = threshold, window = window, banfor = banfor }
end

-- Determine which new fields would be added for capacity preflight.
local needed = { [1] = 0, [2] = 0 }
for _, p in ipairs(policies) do
  local scope_idx = (p.scope == "global") and 1 or 2
  if not state[scope_idx]["m:" .. p.fp] then needed[scope_idx] = needed[scope_idx] + 1 end
end
for i = 1, 2 do
  if field_count[i] + needed[i] > 64 then return cjson.encode({ error = "field_limit" }) end
end

local triggers = { [1] = nil, [2] = nil }
local changed = { [1] = {}, [2] = {} }

for _, p in ipairs(policies) do
  local scope_idx = (p.scope == "global") and 1 or 2
  local skip = false
  if state[scope_idx]["ban"] then
    local ok, ban = pcall(cjson.decode, state[scope_idx]["ban"])
    if ok and tonumber(ban.expires_at_ms) > now then
      if ban.trigger == reqid then
        -- duplicate replay: report the original ban, do not extend it
        triggers[scope_idx] = { replay = ban }
      end
      -- another admitted request created this ban: skip strikes in this scope
      if tonumber(ban.created_at_ms) > admitted then skip = true end
    end
  end
  -- An operator unban's suppression window blocks new match strikes (not rate
  -- buckets) in the selected scope until it expires.
  local scope_name = scopes[scope_idx]
  if suppressed_until[scope_name] and suppressed_until[scope_name] > now then skip = true end

  if not skip then
    local field = "m:" .. p.fp
    local obj = { ids = {}, ts = {} }
    if state[scope_idx][field] then
      local ok, decoded = pcall(cjson.decode, state[scope_idx][field])
      if ok then obj = decoded end
    end
    local ids, ts = {}, {}
    for j, t in ipairs(obj.ts or {}) do
      if tonumber(t) > now - p.window then
        ids[#ids + 1] = obj.ids[j]
        ts[#ts + 1] = t
      end
    end
    local seen = false
    for _, id in ipairs(ids) do if id == reqid then seen = true end end
    if not seen then
      ids[#ids + 1] = reqid
      ts[#ts + 1] = now
    end
    local count = #ids
    changed[scope_idx][field] = cjson.encode({ ids = ids, ts = ts, t = now, exp = now + p.window + p.banfor + 30000 })
    if count >= p.threshold then
      local candidate = { fp = p.fp, id = p.id, threshold = p.threshold, window = p.window, banfor = p.banfor, ids = ids, count = count }
      local current = triggers[scope_idx]
      if not current or candidate.banfor > current.banfor or (candidate.banfor == current.banfor and candidate.id < current.id) then
        triggers[scope_idx] = candidate
      end
    end
  end
end

local bans = {}
for i = 1, 2 do
  local t = triggers[i]
  if t and t.replay then
    bans[#bans + 1] = t.replay
  elseif t and t.fp then
    local expires = now + t.banfor
    local qualifying = {}
    for _, p in ipairs(policies) do qualifying[#qualifying + 1] = p.id end
    local ban = {
      scope = scopes[i], policy_id = t.id, fingerprint = t.fp, revision = revision,
      qualifying = qualifying, trigger = reqid, count = t.count,
      window_ms = t.window, created_at_ms = now, expires_at_ms = expires
    }
    redis.call("DEL", KEYS[i])
    -- Preserve rate fields with their own logical expiries. The hash TTL must
    -- cover every live field, not just the ban, or a long-period bucket is
    -- silently destroyed when a short ban is created.
    local preserved = {}
    for field, raw in pairs(state[i]) do
      if field:sub(1, 2) == "r:" then
        redis.call("HSET", KEYS[i], field, raw)
        preserved[field] = raw
      end
    end
    local ban_raw = cjson.encode(ban)
    redis.call("HSET", KEYS[i], "ban", ban_raw)
    preserved["ban"] = ban_raw
    local maxexp = max_expiry(preserved, now + t.banfor + t.window + 30000)
    redis.call("PEXPIRE", KEYS[i], maxexp - now)
    bans[#bans + 1] = ban
  else
    for field, raw in pairs(changed[i]) do
      redis.call("HSET", KEYS[i], field, raw)
    end
    if next(changed[i]) then
      local all = {}
      for field, raw in pairs(state[i]) do all[field] = raw end
      for field, raw in pairs(changed[i]) do all[field] = raw end
      local maxexp = max_expiry(all, now + 30000)
      redis.call("PEXPIRE", KEYS[i], maxexp - now)
    end
  end
end

return cjson.encode({ now_ms = now, bans = bans, rejected = rejected })
