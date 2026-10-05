//go:build !linux

package ble

import (
	"errors"
	"time"
)

func openUserChannel(dev int, unblock bool, logf func(string, ...any)) (hciTransport, func(), error) {
	return nil, nil, errors.New("ble: the HCI user channel is only available on Linux")
}

func openUserChannelWait(dev int, unblock bool, wait time.Duration, logf func(string, ...any)) (hciTransport, func(), error) {
	return openUserChannel(dev, unblock, logf)
}
