package autoban

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// NewAdminSocket binds only the configured Unix socket with mode 0600. A
// regular file at the bind path is never removed.
func NewAdminSocket(path string, handler http.Handler) (*http.Server, net.Listener, error) {
	if path == "" {
		return nil, nil, fmt.Errorf("autoban: empty admin socket path")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("autoban: admin socket path is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, fmt.Errorf("autoban: removing stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("autoban: checking admin socket path: %w", err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, nil, fmt.Errorf("autoban: setting admin socket mode: %w", err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	return server, listener, nil
}
