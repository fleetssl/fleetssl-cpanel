package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/boltdb/bolt"
	log "github.com/sirupsen/logrus"
)

func openBolt() (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.WithField("panic", r).WithField("file", config.DbPath).Warn("BoltDB panicked, so we are removing the database file")
			os.Rename(config.DbPath, fmt.Sprintf("%s.bak-%d", config.DbPath, time.Now().Unix()))
			err = fmt.Errorf("Bolt panic: %v", r)
		}
	}()
	db, err = bolt.Open(config.DbPath, 0600, &bolt.Options{
		Timeout: 5 * time.Second,
	})
	if err == bolt.ErrTimeout {
		log.WithError(err).WithField("file", config.DbPath).Warn("BoltDB experienced a timeout on open, giving up")
	} else if err != nil {
		log.WithError(err).WithField("file", config.DbPath).Warn("BoltDB experienced an error, so we are removing the database file")
		os.Rename(config.DbPath, fmt.Sprintf("%s.bak-%d", config.DbPath, time.Now().Unix()))
	}
	return
}

// You must close the transaction manually if using this helper
func dbOpenBucket(bucketName string, f func(*bolt.Bucket, *bolt.Tx) error) error {
	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return f(bucket, tx)
	})
}

func dbFetchBucket(bucketName string, key string, out interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Bolt panicked: %v", r)
		}
	}()

	return dbOpenBucket(bucketName, func(bucket *bolt.Bucket, tx *bolt.Tx) error {
		return dbFetch(bucket, key, out)
	})
}

func dbPutBucket(bucketName string, key string, v interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Bolt panicked: %v", r)
		}
	}()

	return dbOpenBucket(bucketName, func(bucket *bolt.Bucket, tx *bolt.Tx) error {
		return dbPut(bucket, key, v)
	})
}

func dbRemoveBucket(bucketName string, key string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Bolt panicked: %v", r)
		}
	}()

	return dbOpenBucket(bucketName, func(bucket *bolt.Bucket, tx *bolt.Tx) error {
		return bucket.Delete([]byte(key))
	})
}

func dbFetch(bucket *bolt.Bucket, key string, out interface{}) error {
	v := bucket.Get([]byte(key))
	if v == nil {
		return nil
	}
	return json.Unmarshal(v, out)
}

func dbPut(bucket *bolt.Bucket, key string, v interface{}) error {
	buf, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(key), buf)
}

type renewalAttemptState struct {
	Root        string `json:"root"`
	Attempts    int    `json:"attempts_count"`
	LastAttempt int64  `json:"last_attempt"`
	LastError   string `json:"last_error"`
}

func (ras renewalAttemptState) IsZero() bool {
	return ras.Root == ""
}
