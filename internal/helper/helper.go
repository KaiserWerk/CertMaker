package helper

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// GetUserIP returns the client's IP address.
func GetUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	fmt.Println("X Real IP " + IPAddress)
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For") // should I use that?
		fmt.Println("X Forwarded For " + IPAddress)
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
		fmt.Println("Remote Addr " + IPAddress)
	}

	//if strings.Contains(IPAddress, ":") {
	//	parts := strings.Split(IPAddress, ":")
	//	IPAddress = strings.Join(parts[:len(parts)-1], ":")
	//}

	host, _, err := net.SplitHostPort(IPAddress)
	if err != nil {
		return ""
	}
	fmt.Println("Host: " + host)

	if host == "::1" {
		return "127.0.0.1"
	}

	return host
}



