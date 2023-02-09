package daemon

import (
	"encoding/json"
	"time"

	"os"

	log "github.com/sirupsen/logrus"
	"github.com/boltdb/bolt"
)

var forceReportCh chan struct{}

func init() {
	forceReportCh = make(chan struct{})
}

func runReports(exitCh chan<- error) {
	for {
		var out string
		if err := dbFetchBucket("state", "reporting_next_run", &out); err != nil || out == "" {
			log.WithError(err).Warn("reporting_next_run not set, assuming +24h")
			out = time.Now().Add(24 * time.Hour).Format(time.RFC3339)
		}
		t, err := time.Parse(time.RFC3339, out)
		if err != nil {
			log.WithError(err).Warn("reporting_next_run was unparseable, assuming now")
			t = time.Now()
		}

		log.WithField("time", t).Info("Next report time")

		if t.After(time.Now()) {
			select {
			case <-time.After(t.Sub(time.Now())):
				log.Debug("Time elapsed, time for reporting!")
			case <-forceReportCh:
				log.Info("Got force report, running now!")
			}
		}

		log.Info("Processing reports now")
		processReports()
		log.Info("Reporting done")
	}
}

type report struct {
	IsFailure bool      `json:"is_failure"`
	User      string    `json:"user"`
	Domain    string    `json:"domain"`
	Message   string    `json:"reason"`
	When      time.Time `json:"when"`
}

func addReport(r report) error {
	if err := dbOpenBucket("reporting", func(b *bolt.Bucket, tx *bolt.Tx) error {
		buf, _ := json.Marshal(r)
		return b.Put([]byte(time.Now().Format(time.StampNano)), buf)
	}); err != nil {
		return err
	}
	return nil
}

func processReports() {
	reports := []report{}
	if err := dbOpenBucket("reporting", func(b *bolt.Bucket, tx *bolt.Tx) error {
		c := b.Cursor()
		var out report
		for k, v := c.First(); k != nil; k, v = c.Next() {
			log.
				WithField("k", string(k)).
				WithField("v", string(v)).Debug("Got a report")

			if err := json.Unmarshal(v, &out); err != nil {
				log.WithField("report", string(v)).Warn("Failed to unmarshal report")
				continue
			}

			reports = append(reports, out)
		}
		return nil
	}); err != nil {
		log.WithError(err).Error("Failed to process reporting")
		// we are not returning here intentionally so that the reporting hopefully gets cleaned up after
	}

	failures := []report{}
	successes := []report{}
	for _, r := range reports {
		if r.IsFailure && config.Reporting.Failures {
			failures = append(failures, r)
		} else if !r.IsFailure && config.Reporting.Successes {
			successes = append(successes, r)
		}
	}

	if (len(failures) > 0 || len(successes) > 0) || config.Reporting.SendEmpty {
		// If this fails, we don't retry and just move on and
		// delete the report data, so it doesn't queue up
		if err := sendReports(failures, successes); err != nil {
			log.WithError(err).Error("Failed to send report")
			// again, intentionally not returning here
		}
	}

	// Set the next run time of reporting
	dur, err := time.ParseDuration(config.Reporting.Interval)
	if err != nil {
		log.WithField("dur", config.Reporting.Interval).Warn("Failed to parse reporting.interval, falling back to 24h")
		dur, _ = time.ParseDuration("24h")
	}
	if err := dbPutBucket("state", "reporting_next_run", time.Now().Add(dur).Format(time.RFC3339)); err != nil {
		log.WithError(err).Error("Failed to persist reporting_next_run")
		// intentionally not returning as the remaining code needs to run
	}

	// Delete all the jobs
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte("reporting"))
	}); err != nil {
		log.WithError(err).Error("Failed to clear reporting db")
	}
}

func sendReports(failures, successes []report) error {
	mailTpl, err := GetMailTemplate("en", MailTemplateReport)
	if err != nil {
		return err
	}

	hn, err := os.Hostname()
	if hn == "" {
		hn = "Error:" + err.Error()
	}

	return SendMail(GetAdminEmail(), mailTpl.Subject, mailTpl.Body, mailTpl.Html, MailArgs{
		"Date":      time.Now(),
		"Failures":  failures,
		"Successes": successes,
		"Hostname":  hn,
	}, config.Insecure)
}
