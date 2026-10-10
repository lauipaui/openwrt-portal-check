//go:build !linux

package main

import (
	"errors"
	"os"
	"path/filepath"
)

// Portable test/development lock. Linux production uses advisory flock and
// automatic release on process exit. A killed non-Linux CLI can leave this dir.
func stateLock(config string) (func(), error) {
	p := filepath.Join(filepath.Dir(config), ".portal-state.lockdir")
	if e := os.Mkdir(p, 0700); e != nil {
		return nil, errors.New("another state writer or stale test lock is present")
	}
	return func() { os.Remove(p) }, nil
}
