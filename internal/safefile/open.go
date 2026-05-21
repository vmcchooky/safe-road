package safefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type File struct {
	*os.File
	root *os.Root
}

// Open opens a caller-supplied file path through an os.Root scoped to the
// cleaned parent directory, avoiding traversal during final path resolution.
func Open(path string) (*File, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}

	cleaned := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(cleaned))
	if err != nil {
		return nil, err
	}

	file, err := root.Open(filepath.Base(cleaned))
	if err != nil {
		_ = root.Close()
		return nil, err
	}

	return &File{File: file, root: root}, nil
}

func (f *File) Close() error {
	if f == nil {
		return nil
	}

	fileErr := f.File.Close()
	rootErr := f.root.Close()
	if fileErr != nil {
		return fileErr
	}
	return rootErr
}

// ReadFile reads a caller-supplied file path using Open.
func ReadFile(path string) ([]byte, error) {
	file, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return io.ReadAll(file)
}
