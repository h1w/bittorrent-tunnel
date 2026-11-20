package service

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFile atomically writes data to path, creating parent directories with
// mode 0o700 if needed. The final file is created with the requested mode.
// It is used for all root-owned btawg configuration files.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	return writeFile(path, bytes.NewReader(data), mode)
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".btawg-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = io.Copy(f, r); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return os.Rename(f.Name(), path)
}
