//go:build !windows

package dhcp

import (
	"syscall"
)

// broadcastControl enables SO_BROADCAST on the socket.
func broadcastControl(network, address string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}
