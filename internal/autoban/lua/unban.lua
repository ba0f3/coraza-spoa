-- UNBAN: one atomic scope reset with a 120s idempotency receipt.
local scope, operation, digest, nonce = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
local suppress = tonumber(ARGV[5])
local now = now_ms()

local existing = redis.call("GET", KEYS[3])
if existing then
  local ok, receipt = pcall(cjson.decode, existing)
  if ok then
    if receipt.digest ~= digest then return cjson.encode({ error = "conflict" }) end
    receipt.replayed = true
    return cjson.encode(receipt)
  end
end

local existed = redis.call("EXISTS", KEYS[1]) == 1
redis.call("DEL", KEYS[1])
local suppression_end = suppress > 0 and (now + suppress) or (now + 60000)
local retention = math.max(120000, suppress + 30000)
redis.call("HSET", KEYS[2], "nonce", nonce)
redis.call("HSET", KEYS[2], "suppressed_until", suppression_end)
redis.call("HSET", KEYS[2], "expires_at", now + retention)
redis.call("PEXPIRE", KEYS[2], retention)

local result = {
  state_existed = existed,
  replayed = false,
  remaining_application_bans_evaluated = (scope == "global") and false or true,
  nonce = nonce,
  reset_at_ms = now,
  suppressed_until_ms = suppression_end,
  operation = operation,
  digest = digest,
  other_ban = cjson.null
}

if scope == "application" and KEYS[4] then
  local raw = redis.call("HGET", KEYS[4], "ban")
  if raw then
    local ok, ban = pcall(cjson.decode, raw)
    if ok and tonumber(ban.expires_at_ms) > now then result.other_ban = ban end
  end
end

redis.call("SET", KEYS[3], cjson.encode(result), "PX", 120000)
return cjson.encode(result)
