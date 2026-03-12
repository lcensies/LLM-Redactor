package utils

import (
	"os"
	"path/filepath"
	"strings"
)

func ExpandTilde(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}
