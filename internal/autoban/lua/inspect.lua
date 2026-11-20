-- INSPECT: report both scopes without refreshing any TTL.
local now = now_ms()
local state = { read_state(KEYS[1], now), read_state(KEYS[2], now) }
local scopes = { "global", "application" }
local bans, suppressed = {}, {}
for i = 1, 2 do
  local raw = state[i]["ban"]
  if raw then
    local ok, ban = pcall(cjson.decode, raw)
    if ok and tonumber(ban.expires_at_ms) > now then bans[#bans + 1] = ban end
  end
  local sup = tonumber(redis.call("HGET", KEYS[2 + i], "suppressed_until") or "0")
  if sup > now then suppressed[#suppressed + 1] = { scope = scopes[i], until_ms = sup } end
end
return cjson.encode({ now_ms = now, bans = bans, suppressed = suppressed })
