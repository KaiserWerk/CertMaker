package jobs

import (
	"time"

	"github.com/KaiserWerk/CertMaker/internal/cron"
)

var GenerateCTLsJob = cron.NewJob("Generate CRLs", true, 24*time.Hour, func(deps *cron.Dependencies) error {
	return nil
})
