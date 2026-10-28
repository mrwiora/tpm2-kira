// Package wipe overwrites secrets in memory once they are used.
package wipe

import "runtime"

// wipe overwrites a key where it is; the full capacity, in case a shorter
// view of it is handed in.
func Bytes(b []byte) {
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
