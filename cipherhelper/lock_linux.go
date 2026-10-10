//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func stateLock(config string) (func(), error) {
	dir := filepath.Dir(config)
	st, e := os.Stat(dir)
	if e != nil {
		return nil, e
	}
	if st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("state directory must not be group/world writable")
	}
	p := filepath.Join(dir, ".portal-state.lock")
	if st, e = os.Lstat(p); e == nil && !st.Mode().IsRegular() {
		return nil, errors.New("unsafe state lock")
	}
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another portal state writer is active")
	}
	return func() { syscall.Flock(fd, syscall.LOCK_UN); f.Close() }, nil
}
