package daemon

import (
	"testing"
	"time"
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestShouldRunRenewals(tt *testing.T) {
	table := []struct {
		now      time.Time
		days     []string
		times    [2]int
		expected bool
	}{
		{
			mustParseTime("2016-12-18 09:00:00"),
			[]string{"Sunday"},
			[2]int{9, 17},
			true,
		},
		{
			mustParseTime("2016-12-18 09:00:00"),
			[]string{"Monday"},
			[2]int{0, 0},
			false,
		},
		{
			mustParseTime("2016-12-18 09:00:00"),
			[]string{"Sunday"},
			[2]int{10, 17},
			false,
		},
	}

	for _, t := range table {
		config.RenewalDaysOfWeek = t.days
		config.RenewalTimeOfDay = &(t.times)

		if res := shouldRunRenewals(t.now); res != t.expected {
			tt.Fatalf("Wanted %v, got %v for %#v", res, t.expected, t)
		}
	}
}
