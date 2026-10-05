//go:build !linux

package ble

import "errors"

func openUserChannel(dev int, unblock bool, logf func(string, ...any)) (hciTransport, func(), error) {
	return nil, nil, errors.New("ble: the HCI user channel is only available on Linux")
}
