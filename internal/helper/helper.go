package helper

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TrimSliceElements removes whitespace from all elements
// of a string slice
func TrimSliceElements(parts []string) {
	for k, v := range parts {
		parts[k] = strings.TrimSpace(v)
	}
}

// Visit returns a function for finding a list of file
// matching certain criteria.
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

// DoesFileExist check whether the file f exists.
func DoesFileExist(f string) bool {
	info, err := os.Stat(f)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// StringSliceContains returns true if the string key
// exists in the string slice s.
func StringSliceContains(s []string, key string) bool {
	for _, v := range s {
		if v == key {
			return true
		}
	}

	return false
}

func Retry(attempts uint, sleep time.Duration, f func() error) error {
	if err := f(); err != nil {
		if attempts--; attempts > 0 {
			time.Sleep(sleep)
			return Retry(attempts, sleep+1*time.Second, f)
		}
		return err
	}

	return nil
}
