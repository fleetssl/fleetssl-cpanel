package common

// These are alternatives to user.Lookup for Linux platform
// because we are disabling cgo.

import (
	"math"
	"os/exec"
	"strconv"
	"strings"
)

func FindUid(user string) (uint32, error) {
	return id(user, "-u")
}

func FindGid(user string) (uint32, error) {
	return id(user, "-g")
}

func id(user, flag string) (uint32, error) {
	idCmd, err := exec.LookPath("id")
	if err != nil {
		return math.MaxUint32, err
	}

	cmd := exec.Command(idCmd, flag, user)
	out, err := cmd.Output()
	if err != nil {
		return math.MaxUint32, err
	}

	buf := strings.TrimSpace(string(out))

	conv, err := strconv.ParseUint(buf, 10, 32)
	if err != nil {
		return math.MaxUint32, err
	}

	return uint32(conv), nil
}
