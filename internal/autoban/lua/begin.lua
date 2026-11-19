-- BEGIN: atomic admission. Reads only; rate buckets consume when all match.
local mode, app, iphex, revision, reqid = ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5]
local nrates = tonumber(ARGV[6])
local now = now_ms()

local state = { read_state(KEYS[1], now), read_state(KEYS[2], now) }
local scopes = { "global", "application" }
local fences = {}
for i = 1, 2 do
  local nonce = redis.call("HGET", KEYS[2 + i], "nonce") or "none"
  local sup = tonumber(redis.call("HGET", KEYS[2 + i], "suppressed_until") or "0")
  fences[scopes[i]] = { nonce = nonce, suppressed_until = sup }
end

-- Preflight: reject future stored timestamps and oversized fields.
for i = 1, 2 do
  for field, raw in pairs(state[i]) do
    if #raw > 65536 then return cjson.encode({ error = "field_limit" }) end
    local ok, obj = pcall(cjson.decode, raw)
    if ok and type(obj) == "table" and obj.t and tonumber(obj.t) > now then
      return cjson.encode({ error = "clock_regression" })
    end
  end
end

local bans = {}
for i = 1, 2 do
  local b = state[i]["ban"]
  if b then
    local ok, obj = pcall(cjson.decode, b)
    if ok and tonumber(obj.expires_at_ms) > now then
      bans[#bans + 1] = obj
    end
  end
end

-- Evaluate all matching rate buckets atomically.
local rates = {}
local throttle_id, retry = "", 0
local idx = 7
for _ = 1, nrates do
  local fp, requests, period, burst = ARGV[idx], tonumber(ARGV[idx + 1]), tonumber(ARGV[idx + 2]), tonumber(ARGV[idx + 3])
  idx = idx + 4
  local field = "r:" .. fp
  local raw = state[2][field]
  local tokens, last = burst, now
  if raw then
    local ok, obj = pcall(cjson.decode, raw)
    if ok then
      tokens, last = tonumber(obj.tokens), tonumber(obj.t)
      if last > now then return cjson.encode({ error = "clock_regression" }) end
      local elapsed = now - last
      local full_ms = (burst - tokens) * period / requests
      if elapsed > full_ms then elapsed = full_ms end
      tokens = math.min(burst, tokens + math.floor(elapsed * requests / period))
    end
  end
  rates[#rates + 1] = { fp = fp, tokens = tokens, requests = requests, period = period, burst = burst }
end

for _, r in ipairs(rates) do
  if r.tokens < 1 then
    local need_ms = math.ceil(r.period / r.requests / 1000)
    if need_ms < 1 then need_ms = 1 end
    retry = math.max(retry, need_ms)
    if throttle_id == "" then throttle_id = r.fp end
  end
end

if throttle_id == "" then
  for _, r in ipairs(rates) do
    local field = "r:" .. r.fp
    local tokens = r.tokens - 1
    redis.call("HSET", KEYS[2], field, cjson.encode({ tokens = tokens, t = now, exp = now + math.max(30000, r.period * r.burst / r.requests) }))
    local ttl = 30000
    local hash_ttl = redis.call("TTL", KEYS[2]) or -1
    if hash_ttl > 0 and hash_ttl * 1000 > ttl then ttl = hash_ttl * 1000 end
    redis.call("PEXPIRE", KEYS[2], ttl)
  end
end

local out = { now_ms = now, bans = bans, throttle_policy_id = throttle_id, retry_after_seconds = retry, fences = {}, suppressed = {} }
for i = 1, 2 do
  out.fences[#out.fences + 1] = { scope = scopes[i], nonce = fences[scopes[i]].nonce }
  out.suppressed[#out.suppressed + 1] = { scope = scopes[i], until_ms = fences[scopes[i]].suppressed_until }
end
return cjson.encode(out)
