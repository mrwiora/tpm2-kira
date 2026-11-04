//go:build !linux

package ble

import (
	"errors"
	"io"
	"time"
)

func openUserChannel(dev int, unblock bool, rfkill io.Writer, logf func(string, ...any)) (hciTransport, func(), error) {
	return nil, nil, errors.New("ble: the HCI user channel is only available on Linux")
}

func openUserChannelWait(dev int, unblock bool, rfkill io.Writer, wait time.Duration, cancel <-chan struct{}, logf func(string, ...any)) (hciTransport, func(), error) {
	return openUserChannel(dev, unblock, rfkill, logf)
}
