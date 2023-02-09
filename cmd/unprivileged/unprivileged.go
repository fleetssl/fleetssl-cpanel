package unprivileged

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func CreateFileUnprivileged(args []string) {
	if len(args) < 3 {
		os.Exit(1)
	}
	filename, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	contents, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := createFile(string(filename), string(contents), strings.Join(args[2:], " ")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(0)
}

// this code path must only run under
// a process that has reduced privileges
// it has no protection agaisnt symlink attacks
// and must not run as root.
func createFile(name, contents, path string) error {
	// can't use user.Current to check not running under root because cgo
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(path, name))
	if err != nil {
		return err
	}
	_, err = f.WriteString(contents)
	if err != nil {
		return err
	}
	return nil
}
