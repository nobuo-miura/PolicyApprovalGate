//go:build windows

package audit

import (
	"fmt"
	"os"
)

func openNoFollow(path string, perm os.FileMode) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && (!before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("audit log is not a regular file")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || (before != nil && !os.SameFile(before, after)) {
		_ = f.Close()
		return nil, fmt.Errorf("audit log changed while opening")
	}
	return f, nil
}
