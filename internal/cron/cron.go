package cron

import (
	"context"
	"time"

	"github.com/KaiserWerk/CertMaker/internal/configuration"
	"github.com/KaiserWerk/CertMaker/internal/dbservice"
	"github.com/KaiserWerk/CertMaker/internal/entity"

	"github.com/sirupsen/logrus"
)

type Cron struct {
	jobs []Job
	deps *Dependencies
	ctx  context.Context
	cf   func()
}

type Dependencies struct {
	Config *configuration.AppConfig
	Logger *logrus.Entry
	DBSvc  *dbservice.DBService
}

func New(deps *Dependencies) *Cron {
	cron := Cron{
		jobs: make([]Job, 0, 3),
		deps: deps,
	}
	cron.ctx, cron.cf = context.WithCancel(context.Background())

	return &cron
}

func (c *Cron) GetAllJobInfo() []entity.JobInfo {
	var jobInfos []entity.JobInfo
	for _, j := range c.jobs {
		jobInfos = append(jobInfos, entity.JobInfo{
			ID:       j.ID,
			Caption:  j.Caption,
			Interval: j.Interval.String(),
		})
	}
	return jobInfos
}

func (c *Cron) AddDaily(j Job) {
	c.jobs = append(c.jobs, j)
}

func (c *Cron) Run() {
	c.deps.Logger.Tracef("starting up %d cronjob(s)", len(c.jobs))
	t := time.NewTicker(5 * time.Minute)

	// for every job, check the Interval and last execution time
	// this allows for the use of different intervals

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			// 1. retrieve jobs to run
			jobsToRun := c.getJobsToRun()
			if len(jobsToRun) == 0 {
				continue
			}
			// 2. run jobs
			go c.runJobs(jobsToRun)
		}
	}

}

func (c *Cron) getJobsToRun() []Job {
	// comparing the current time with the last execution time of each job
	// respecting the defined interval
	var jobsToRun []Job
	now := time.Now().UTC()
	for _, j := range c.jobs {
		if j.LastExecution.IsZero() {
			c.deps.Logger.Tracef("job '%s' has never been run, scheduling for execution", j.Caption)
			jobsToRun = append(jobsToRun, j)
			continue
		}
		if now.Sub(j.LastExecution) >= j.Interval {
			c.deps.Logger.Tracef("job '%s' is due for execution (last run: %s)", j.Caption, j.LastExecution.String())
			jobsToRun = append(jobsToRun, j)
		} else {
			c.deps.Logger.Tracef("job '%s' is not due for execution (last run: %s)", j.Caption, j.LastExecution.String())
		}
	}
	return jobsToRun
}

func (c *Cron) runJobs(jobsToRun []Job) {
	if len(jobsToRun) == 0 {
		c.deps.Logger.Trace("no jobs queued")
		return
	}
	for _, j := range jobsToRun {
		go func(job Job, fLogger *logrus.Entry) {
			if !job.Enabled {
				fLogger.Tracef("job '%s' is not Enabled, skipping", job.Caption)
				return
			}
			fLogger.Tracef("job '%s' started", job.Caption)
			if err := job.Work(c.deps); err != nil {
				fLogger.Tracef("job '%s' failed: %s", job.Caption, err.Error())
			} else {
				fLogger.Tracef("job '%s' ran successfully", job.Caption)
			}
		}(j, c.deps.Logger)
	}
}

func (c *Cron) Stop() {
	c.deps.Logger.Trace("stopping all cronjobs")
	c.cf()
}
