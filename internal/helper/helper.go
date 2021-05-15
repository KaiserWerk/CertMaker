package helper

import (
	"os"
	"path/filepath"
	"strings"
)

func TrimSliceElements(parts []string) {
	for k, v := range parts {
		parts[k] = strings.TrimSpace(v)
	}
}

func Visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.Contains(path, "-key.pem") {
			return err
		}

		*files = append(*files, path)
		return nil
	}
}

func DoesFileExist(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}




