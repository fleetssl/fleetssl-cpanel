package cpanelcgi

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"github.com/go-ini/ini"
)

const (
	DefaultLocale = "en"
)

var translationLoaded = false
var translationFile *ini.File

var translationLocale = DefaultLocale

func findTranslationFile() string {
	// first try any user created translations
	if file := common.PluginFile(fmt.Sprintf("translate.%s.ini", translationLocale)); common.FileExists(file) {
		return file
	}

	// next try any vendor translation files
	if file := common.PluginFile(fmt.Sprintf("vendor.%s.ini", translationLocale)); common.FileExists(file) {
		return file
	}

	// otherwise print nothing was loaded, but only if the locale isn't english
	if translationLocale != DefaultLocale {
		log.WithField("locale", translationLocale).Println("No translation files exist for locale")
	}

	return ""
}

func loadTranslationFile() {
	file := findTranslationFile()
	if file == "" {
		return
	}
	var err error
	translationFile, err = ini.Load(file)
	if err != nil {
		log.WithError(err).WithField("file", file).Println("Error loading translation file")
	}
}

func SetLocale(locale string) {
	translationLocale = locale
}

func TS(in string) string {
	if !translationLoaded {
		loadTranslationFile()
		// only try once per session to load the translation file
		translationLoaded = true
	}
	if translationFile == nil {
		return in
	}
	section, err := translationFile.GetSection("")
	if err != nil {
		return in
	}
	key, err := section.GetKey(in)
	if err != nil {
		return in
	}
	s := key.String()
	if s == "" {
		return in
	}
	return s
}

func TF(in string, a ...interface{}) string {
	return fmt.Sprintf(TS(in), a...)
}

func TE(in string, a ...interface{}) error {
	return fmt.Errorf(TS(in), a...)
}
