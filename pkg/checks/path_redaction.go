package checks

import (
	"os"
	"path/filepath"
	"strings"
)

func resolveScanRoot(scanRoot string) string {
	if strings.TrimSpace(scanRoot) != "" {
		return filepath.Clean(scanRoot)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Clean(home)
}

func redactHomePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || path == "" {
		return path
	}

	cleanPath := filepath.Clean(path)
	cleanHome := filepath.Clean(home)
	if cleanPath == cleanHome {
		return "$HOME"
	}

	prefix := cleanHome + string(filepath.Separator)
	if strings.HasPrefix(cleanPath, prefix) {
		return "$HOME" + string(filepath.Separator) + strings.TrimPrefix(cleanPath, prefix)
	}
	return cleanPath
}
