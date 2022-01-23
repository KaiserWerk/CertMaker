package logging

import (
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"
)

const (
	defaultTimestampFormat string = "2006-01-02 15:04:05.000000"
	defaultLogFormat       string = "%time% [%level%] [%context%] %msg% %meta%"
)

type MyFormatter struct {
	TimestampFormat string
	LogFormat       string
	LevelPadding    uint8
	ContextPadding  uint8
}

func (f *MyFormatter) Format(e *logrus.Entry) ([]byte, error) {
	timestampFormat := defaultTimestampFormat
	if f.TimestampFormat != "" {
		timestampFormat = f.TimestampFormat
	}
	logFormat := defaultLogFormat
	if f.LogFormat != "" {
		logFormat = f.LogFormat
	}

	line := strings.Replace(logFormat, "%time%", e.Time.Format(timestampFormat), 1)
	line = strings.Replace(line, "%level%", fmt.Sprintf("%*s", f.LevelPadding, strings.ToUpper(e.Level.String())), 1)
	if context, ok := e.Data["context"]; ok && context != nil {
		line = strings.Replace(line, "%context%", fmt.Sprintf("%*s", f.ContextPadding, context.(string)), 1)
		delete(e.Data, "context")
	} else {
		line = strings.Replace(line, "%context%", fmt.Sprintf("%*s", f.ContextPadding, strings.ToUpper("MissCtx")), 1)
	}
	line = strings.Replace(line, "%msg%", e.Message, 1)

	if len(e.Data) > 0 {
		meta, err := json.Marshal(e.Data)
		if err != nil {
			return nil, err
		}

		line = strings.Replace(line, "%meta%", string(meta), 1)
	} else {
		line = strings.Replace(line, "%meta%", "", 1)
	}

	return []byte(strings.TrimSpace(line) + "\n"), nil
}
