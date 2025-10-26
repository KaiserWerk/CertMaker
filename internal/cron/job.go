package cron

import (
	"sync/atomic"
	"time"
)

var counter uint32 = 0

type Job struct {
	ID            uint32
	Caption       string
	Enabled       bool
	Interval      time.Duration
	LastExecution time.Time
	Work          func(*Dependencies) error
}

func NewJob(name string, enabled bool, interval time.Duration, work func(deps *Dependencies) error) Job {
	return Job{
		ID:       atomic.AddUint32(&counter, 1),
		Caption:  name,
		Enabled:  enabled,
		Interval: interval,
		Work:     work,
	}
}
