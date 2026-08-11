//go:build !windows

package audit

import (
	"fmt"
	"os"
	"syscall"
)

func openNoFollow(path string, perm os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_APPEND|syscall.O_CREAT|syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, uint32(perm.Perm()))
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create file handle for audit log")
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("audit log is not a regular file")
	}
	return f, nil
}
