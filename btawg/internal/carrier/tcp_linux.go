package carrier

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// TCPControl gives the outer carrier room for a WAN-sized flight and uses
// BBR where available. No host setting or unrelated socket is changed.
func TCPControl(_, _ string, conn syscall.RawConn) error {
	var optionErr error
	if err := conn.Control(func(fd uintptr) {
		// Linux doubles the requested size and caps it at net.core.rmem_max.
		// Set before connect/listen so window scaling covers the buffer.
		if optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20); optionErr != nil {
			return
		}
		if optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20); optionErr != nil {
			return
		}
		optionErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	}); err != nil {
		return err
	}
	if optionErr == nil || errors.Is(optionErr, unix.ENOENT) || errors.Is(optionErr, unix.EPERM) || errors.Is(optionErr, unix.ENOPROTOOPT) {
		return nil // retain the host's algorithm if BBR isn't available to this process
	}
	return fmt.Errorf("set TCP carrier congestion control: %w", optionErr)
}
