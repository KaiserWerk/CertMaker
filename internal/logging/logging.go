package logging

import "log"

var logger *log.Logger

// SetLogger sets the logger instance.
func SetLogger(l *log.Logger) {
	logger = l
}

// GetLogger gets the logger instance.
func GetLogger() *log.Logger {
	return logger
}
