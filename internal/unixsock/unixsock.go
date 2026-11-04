// Package unixsock is the boot's private sockets: the gate's coordinator
// and the disk's key provider listen on them.
package unixsock

import (
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Listen creates a socket at path in a directory, both only its own user
// can enter. A leftover of an earlier run is replaced.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	old := unix.Umask(0o177)
	l, err := net.Listen("unix", path)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	return l, nil
}
