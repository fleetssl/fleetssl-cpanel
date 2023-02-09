package daemon

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/boltdb/bolt"
)

func makeTestDb() func() {
	fn := fmt.Sprintf("./test-db-%d", time.Now().UnixNano())
	var err error

	// goes to global variable db
	db, err = bolt.Open(fn, 0600, &bolt.Options{
		Timeout: 5 * time.Second,
	})

	if err != nil {
		panic(err)
	}

	return func() {
		db.Close()
		os.Remove(fn)
	}
}

func TestSetUnsetFlagBasic(t *testing.T) {
	defer makeTestDb()()

	exp := time.Now().Add(250 * time.Millisecond).Unix()
	if err := requestSetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}

	_, err := os.Stat(cpanelFlagFileTest)
	if os.IsNotExist(err) {
		t.Error("Flag file should exist but doesnt")
	} else if err != nil {
		t.Fatalf("Unable to stat flag file: %v", err)
	}

	if err := requestUnsetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}
}

func TestSetUnsetFlagMultipleHolders(t *testing.T) {
	defer makeTestDb()()

	exp := time.Now().Add(1 * time.Minute).Unix() // this shouldnt expire in this test
	if err := requestSetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}

	exp2 := time.Now().Add(10 * time.Minute).Unix()
	if err := requestSetFlag(cpanelFlagFileTest, exp2); err != nil {
		t.Fatal(err)
	}

	var out flags
	if err := dbFetchBucket("flagfiles", "flagmap", &out); err != nil {
		t.Fatal(out)
	}

	if len(out[cpanelFlagFileTest]) != 2 {
		t.Fatalf("Expected 2 items in flagmap for test, got %v", out)
	}

	_, err := os.Stat(cpanelFlagFileTest)
	if os.IsNotExist(err) {
		t.Error("Flag file should exist but doesnt")
	} else if err != nil {
		t.Fatalf("Unable to stat flag file: %v", err)
	}

	if err := requestUnsetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(cpanelFlagFileTest)
	if os.IsNotExist(err) {
		t.Error("Flag file should STILL exist but doesnt")
	} else if err != nil {
		t.Fatalf("Unable to stat flag file: %v", err)
	}

	if err := requestUnsetFlag(cpanelFlagFileTest, exp2); err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(cpanelFlagFileTest)
	if !os.IsNotExist(err) {
		t.Fatal("File shouldnt exist anymore but got different error", err)
	}
}

func TestSetUnsetFlagDuplicateTimes(t *testing.T) {
	defer makeTestDb()()

	exp := time.Now().Add(1 * time.Minute).Unix() // this shouldnt expire in this test

	// twice
	if err := requestSetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}
	if err := requestSetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}

	var out flags
	if err := dbFetchBucket("flagfiles", "flagmap", &out); err != nil {
		t.Fatal(out)
	}

	if len(out[cpanelFlagFileTest]) != 2 {
		t.Fatalf("Expected 2 items in flagmap for test, got %v", out)
	}

	if err := requestUnsetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}

	out = nil
	if err := dbFetchBucket("flagfiles", "flagmap", &out); err != nil {
		t.Fatal(out)
	}

	if len(out[cpanelFlagFileTest]) != 1 {
		t.Fatalf("Expected 1 items in flagmap for test, got %v", out)
	}
}

func TestVacuumFlag(t *testing.T) {
	defer makeTestDb()()

	exp := int64(0) // this is definitely in the past
	if err := requestSetFlag(cpanelFlagFileTest, exp); err != nil {
		t.Fatal(err)
	}

	// So, vacuum should definitely 100% delete it
	vacuumed, err := vacuumOnce()
	if err != nil {
		t.Fatal(err)
	}

	if vacuumed != 1 {
		t.Fatalf("Should have vacuumed 1, got %d", vacuumed)
	}
}
