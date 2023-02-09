package common

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/kardianos/osext"
)

// fork an unprivileged process to create the file
func ForkCreateFileUnprivileged(username, filename, rawcontents, path string) error {
	// both username and path come directly from WHM API
	// so an attack to some extent needs to already have
	// comprimised root
	if username == "" || username == "root" {
		return errors.New("Denied")
	}

	bin, err := osext.Executable()
	if err != nil {
		return err
	}

	uid, err := FindUid(username)
	if err != nil {
		return err
	}
	gid, err := FindGid(username)
	if err != nil {
		return err
	}

	contents := base64.StdEncoding.EncodeToString([]byte(rawcontents))
	b64filename := base64.StdEncoding.EncodeToString([]byte(filename))

	cmd := exec.Command(bin, "-mode", "createfile-no-privilege", string(b64filename), string(contents), path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}
	buf, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to create validation file: %v, %s", err, string(buf))
	}

	return nil
}
