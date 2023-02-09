package common

import "strings"

func AppendIfNotExist(list []string, toadd string) []string {
	if toadd == "" {
		return list
	}
	found := false
	for _, item := range list {
		if item == toadd {
			found = true
			break
		}
	}
	if found {
		return list
	} else {
		return append(list, toadd)
	}
}

// Check that at least all the elements of the first list are in the second list
// ie, list1 ⊂ list2
func ArrayProperSubset(list1, list2 []string) bool {
	for _, element1 := range list1 {
		contains := false
		for _, element2 := range list2 {
			if element1 == element2 {
				contains = true
				break
			}
		}
		if !contains {
			return false
		}
	}

	return true
}

func NormalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
