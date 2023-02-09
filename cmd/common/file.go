package common

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
)

func PluginFile(filename string) string {
	return filepath.Join(filepath.Dir(os.Args[0]), filename)
}

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func FileContentsSame(file1, file2 string) bool {
	if !FileExists(file1) || !FileExists(file2) {
		return false
	}

	b1, err := ioutil.ReadFile(file1)
	if err != nil {
		return false
	}

	b2, err := ioutil.ReadFile(file2)
	if err != nil {
		return false
	}

	return bytes.Compare(b1, b2) == 0
}
