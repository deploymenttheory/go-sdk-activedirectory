package acceptance

import (
	"os"
	"path/filepath"
)

// repositoryFile locates retained inputs when go test sets the package directory
// as its working directory. A staged lab binary may instead use a local relative
// path or an explicit fixture environment variable supplied by its collector.
func repositoryFile(name string) string {
	directory, err := os.Getwd()
	if err != nil {
		return name
	}
	for {
		if info, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil && !info.IsDir() {
			return filepath.Join(directory, filepath.FromSlash(name))
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return name
		}
		directory = parent
	}
}
