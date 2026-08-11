//go:build windows

package audit

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func withFileLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return fmt.Errorf("open audit lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("lock audit log: %w", err)
	}
	defer func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped) }()
	return fn()
}
