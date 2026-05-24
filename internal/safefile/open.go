package safefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	*os.File
	root *os.Root
}

// OpenWithin opens requestedPath through an os.Root scoped to rootDir.
// requestedPath may be relative to rootDir, or it may be an existing documented
// root-prefixed path such as ./ops/secrets/name. Paths outside rootDir are
// rejected before final resolution, and os.Root blocks symlink traversal.
func OpenWithin(rootDir, requestedPath string) (*File, error) {
	relativePath, err := relativeWithinRoot(rootDir, requestedPath)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}

	file, err := root.Open(relativePath)
	if err != nil {
		_ = root.Close()
		return nil, err
	}

	return &File{File: file, root: root}, nil
}

// Open opens a path relative to the current directory. Prefer OpenWithin for
// caller-controlled paths that should be sandboxed to a fixed root.
func Open(path string) (*File, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}

	return OpenWithin(".", path)
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

// ReadFileWithin reads requestedPath using OpenWithin.
func ReadFileWithin(rootDir, requestedPath string) ([]byte, error) {
	file, err := OpenWithin(rootDir, requestedPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return io.ReadAll(file)
}

// ReadFile reads a path relative to the current directory. Prefer
// ReadFileWithin for caller-controlled paths that should be sandboxed.
func ReadFile(path string) ([]byte, error) {
	return ReadFileWithin(".", path)
}

func relativeWithinRoot(rootDir, requestedPath string) (string, error) {
	if strings.TrimSpace(rootDir) == "" {
		return "", errors.New("safe file root is required")
	}
	if strings.TrimSpace(requestedPath) == "" {
		return "", errors.New("file path is required")
	}

	rootAbs, err := filepath.Abs(filepath.Clean(rootDir))
	if err != nil {
		return "", err
	}

	cleaned := filepath.Clean(requestedPath)
	var rel string
	if filepath.IsAbs(cleaned) {
		rel, err = filepath.Rel(rootAbs, cleaned)
		if err != nil {
			return "", err
		}
	} else if absRequested, absErr := filepath.Abs(cleaned); absErr == nil && isWithin(rootAbs, absRequested) {
		rel, err = filepath.Rel(rootAbs, absRequested)
		if err != nil {
			return "", err
		}
	} else {
		rel = cleaned
	}

	rel = filepath.Clean(rel)
	if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("file path escapes safe root")
	}

	return rel, nil
}

func isWithin(rootAbs, targetAbs string) bool {
	rel, err := filepath.Rel(rootAbs, filepath.Clean(targetAbs))
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
