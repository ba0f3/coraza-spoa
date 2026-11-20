package autoban

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
)

// ipHex canonicalizes an address to lowercase hex bytes. Mapped IPv4 addresses
// share the IPv4 subject.
func ipHex(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	b := addr.Unmap().AsSlice()
	return hex.EncodeToString(b)
}

// encodeApp is an unambiguous, collision-free encoding for trusted app IDs.
func encodeApp(name string) string {
	return strconv.Itoa(len(name)) + "_" + base64.RawURLEncoding.EncodeToString([]byte(name))
}

// stateKey and fenceKey implement the v1 key layout. Only trusted identifiers
// (prefix, mode, scope, encoded app) and canonical IP bytes enter keys; raw
// paths, headers, and untrusted incoming app text never do.
func stateKey(prefix string, mode Mode, scope Scope, app string, ip netip.Addr) string {
	base := fmt.Sprintf("%s:v1:%s:{%s}:state", prefix, mode, ipHex(ip))
	if scope == ScopeGlobal {
		return base + ":global"
	}
	return base + ":app:" + encodeApp(app)
}

func fenceKey(prefix string, mode Mode, scope Scope, app string, ip netip.Addr) string {
	base := fmt.Sprintf("%s:v1:%s:{%s}:fence", prefix, mode, ipHex(ip))
	if scope == ScopeGlobal {
		return base + ":global"
	}
	return base + ":app:" + encodeApp(app)
}

func adminKey(prefix string, mode Mode, ip netip.Addr, scopeID, operationID string) string {
	return fmt.Sprintf("%s:v1:%s:{%s}:admin:%s:%s", prefix, mode, ipHex(ip), scopeID, operationID)
}

func adminScopeID(scope Scope, app string) string {
	if scope == ScopeGlobal {
		return "global"
	}
	return "app:" + encodeApp(app)
}
