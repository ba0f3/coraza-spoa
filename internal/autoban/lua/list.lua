-- LIST: SCAN state keys only; fences and receipts are never listed.
local pattern = ARGV[1]
local cursor = ARGV[2]
local limit = tonumber(ARGV[3])
local res = redis.call("SCAN", cursor, "MATCH", pattern, "COUNT", 100)
local next_cursor, keys = res[1], res[2]
local bans, examined = {}, 0
for _, key in ipairs(keys) do
  examined = examined + 1
  if #bans < limit then
    local raw = redis.call("HGET", key, "ban")
    if raw then
      local ok, ban = pcall(cjson.decode, raw)
      if ok then bans[#bans + 1] = ban end
    end
  end
end
return cjson.encode({ cursor = next_cursor, examined = examined, bans = bans })
