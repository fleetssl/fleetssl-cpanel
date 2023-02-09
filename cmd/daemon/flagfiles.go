package daemon

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/boltdb/bolt"
	log "github.com/sirupsen/logrus"
)

const (
	cpanelFlagFileUniqueToken       = `---this flag file has been set by fleetssl cpanel and will be automatically removed---`
	cpanelFlagFileDontRestartApache = "/var/cpanel/mgmt_queue/apache_update_no_restart"
	cpanelFlagFileTest              = "/tmp/letsencrypt-test-file"
)

// map of flag:[]expiries
type flags map[string][]int64

func vacuumFlags() {
	for {
		if vacuumed, err := vacuumOnce(); err != nil {
			log.WithError(err).Error("Failed to vacuum")
		} else if vacuumed > 0 {
			log.WithField("number", vacuumed).Info("Vacuumed some flags")
		}
		time.Sleep(60 * time.Second)
	}
}

// returns number of vacuumed flags
func vacuumOnce() (int, error) {
	vacuumed := 0
	// holds a write lock on the whole bucket
	if err := dbOpenBucket("flagfiles", func(bucket *bolt.Bucket, tx *bolt.Tx) error {
		// entire flagfile state is serialized in the flagmap
		var flagMap flags
		if err := dbFetch(bucket, "flagmap", &flagMap); err != nil {
			return err
		}

		// range over all the flagfile state and check if any are fully expired
		// if they are fully expired, unset the flag if it exists
		// after this loop, the flagMap is persisted back into the db
		for flag, exps := range flagMap {
			// in case db file has been comprimised
			if !validateFlag(flag) {
				log.WithField("flag", flag).Warn("Invalid flag")
				continue
			}

			now := time.Now().Unix()
			anyValid := false
			for _, exp := range exps {
				if exp > now {
					anyValid = true
					break
				}
			}

			if anyValid {
				log.WithField("flag", flag).Info("There is still a valid flag request")
				continue
			}

			// silently check if it exists, so we dont spam the log on the next line
			if _, err := os.Stat(flag); os.IsNotExist(err) {
				// blank the flagfile in the map since its now useless because
				// somebody already deleted the flagfile
				delete(flagMap, flag)
				continue
			}

			log.WithField("flag", flag).Info("Will vacuum flag now")

			// do the needful, and if we fail, leave the state for this flag alone
			if err := unsetFlagFile(flag); err != nil {
				log.WithError(err).Error("Failed to unset flag file")
				// continue so we can try again later (or it doesnt exist later)
				continue
			}
			vacuumed++

			// Successfully unset, blank the map
			delete(flagMap, flag)
		}

		return dbPut(bucket, "flagmap", flagMap)
	}); err != nil {
		return vacuumed, err
	}
	return vacuumed, nil
}

func requestSetFlag(flag string, expiry int64) error {
	if err := dbOpenBucket("flagfiles", func(bucket *bolt.Bucket, tx *bolt.Tx) error {

		var flagMap flags
		if err := dbFetch(bucket, "flagmap", &flagMap); err != nil {
			return err
		}

		if flagMap == nil {
			flagMap = flags{}
		}
		if _, ok := flagMap[flag]; !ok {
			flagMap[flag] = []int64{}
		}

		flagMap[flag] = append(flagMap[flag], expiry)

		return dbPut(bucket, "flagmap", flagMap)

	}); err != nil {
		return err
	}
	return setFlagFile(flag)
}

func requestUnsetFlag(flag string, expiry int64) error {
	safeToDelete := true

	if err := dbOpenBucket("flagfiles", func(bucket *bolt.Bucket, tx *bolt.Tx) error {
		var flagMap flags
		if err := dbFetch(bucket, "flagmap", &flagMap); err != nil {
			return err
		}

		if flagMap == nil {
			return nil
		}
		if _, ok := flagMap[flag]; !ok {
			return nil
		}

		// First remove our one
		for k, v := range flagMap[flag] {
			if v == expiry {
				// remove it only once, in case there are dupes
				flagMap[flag] = append(flagMap[flag][:k], flagMap[flag][k+1:]...)
				break
			}
		}

		// And then evaluate if anybody else is holding the flag
		now := time.Now().Unix()
		for _, v := range flagMap[flag] {
			if v > now {
				safeToDelete = false
				break
			}
		}

		return dbPut(bucket, "flagmap", flagMap)

	}); err != nil {
		return err
	}
	if safeToDelete {
		return unsetFlagFile(flag)
	}
	return nil
}

func setFlagFile(flag string) error {
	_, err := os.Stat(flag)
	if err == nil {
		return nil
	}

	isNotExist := os.IsNotExist(err)
	if !isNotExist {
		return err
	}

	return ioutil.WriteFile(flag, []byte(cpanelFlagFileUniqueToken), 0644)
}

func unsetFlagFile(flag string) error {
	_, err := os.Stat(flag)
	if err != nil {
		if os.IsNotExist(err) { // someone already deleted it, we dont care
			return nil
		}
		return err // if we can't stat it and we expect to be able to, that is seriously bad news
	}

	buf, err := ioutil.ReadFile(flag)
	if err != nil {
		return err
	}

	if string(buf) != cpanelFlagFileUniqueToken {
		log.WithField("Contents", string(buf)).Warn("Flag file contained wrong contents when we went to remove it")
		return nil
	}

	// There is the potential for a race right here
	// Therefore it is important to minimize the time during which the flag exists

	return os.Remove(flag)
}

func validateFlag(flag string) bool {
	if flag == cpanelFlagFileDontRestartApache {
		return true
	}
	if flag == cpanelFlagFileTest {
		return true
	}
	return false
}
