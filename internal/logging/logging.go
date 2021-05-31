package logging

import log "github.com/sirupsen/logrus"

var logger *log.Entry

// SetLogger sets the logger instance.
func SetLogger(l *log.Entry) {
	logger = l
}

// GetLogger gets the logger instance.
func GetLogger() *log.Entry {
	return logger
}
