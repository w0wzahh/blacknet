//go:build windows

package dhcp

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// broadcastControl enables SO_BROADCAST on the socket.
func broadcastControl(network, address string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}
