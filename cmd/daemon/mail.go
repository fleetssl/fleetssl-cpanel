package daemon

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"text/template"

	"gopkg.in/gomail.v2"

	"errors"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"github.com/go-ini/ini"
	"github.com/kardianos/osext"
)

const (
	MailTemplateSuccess     = "success"
	MailTemplateFailure     = "failure"
	MailTemplateNvdataError = "nvdata_error"
	MailTemplatePreError    = "pre_error"
	MailTemplateReport      = "report"
)

type MailTemplate struct {
	Subject string
	Body    string
	Html    string
}

var MailTest = false

type MailArgs map[string]interface{}

func parseTemplate(t string, args MailArgs) (string, error) {
	tpl, err := template.New("").Parse(t)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %v", err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, args); err != nil {
		return "", fmt.Errorf("Error executing template: %v", err)
	}
	return buf.String(), nil
}

// If `to` is empty, then it will default to 'root@$(hostname)'
// `subject` is a template
// `bodyText` is a template
// `bodyHtml` is a template
// `args` will be passed to each template
// `insecure` specifies the security of the mailer client TLS client
func SendMail(to, subject, bodyText, bodyHtml string, args MailArgs, insecure bool) error {

	parsedSubject, err := parseTemplate(subject, args)
	if err != nil {
		return fmt.Errorf("Error with mail subject: %v", err)
	}
	parsedBodyText, err := parseTemplate(bodyText, args)
	if err != nil {
		return fmt.Errorf("Error with mail body text: %v", err)
	}
	parsedBodyHtml, err := parseTemplate(bodyHtml, args)
	if err != nil {
		return fmt.Errorf("Error with mail body html: %v", err)
	}

	hn, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("Error looking up hostname - %v", err)
	}

	from := config.ExternalMailServer.FromAddress
	if from == "" {
		from = "root@" + hn
	}

	if to == "" {
		to = from
	}

	dest := strings.Split(to, ",") // TODO: this should probably also split on semicolons too

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", dest...)
	m.SetHeader("Subject", parsedSubject)
	m.SetBody("text/plain", parsedBodyText)
	if parsedBodyHtml != "" {
		m.AddAlternative("text/html", parsedBodyHtml)
	}

	host := config.ExternalMailServer.Host
	if host == "" {
		host = hn
	}

	port := config.ExternalMailServer.Port
	if port == 0 {
		port = 25
	}

	var d *gomail.Dialer

	if config.ExternalMailServer.Username != "" {
		d = gomail.NewPlainDialer(host, port, config.ExternalMailServer.Username, config.ExternalMailServer.Password)
	} else {
		d = &gomail.Dialer{Host: hn, Port: port, SSL: port == 465}
	}

	if insecure || config.ExternalMailServer.Insecure {
		d.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return d.DialAndSend(m)
}

func readAll(f string) string {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return ""
	}
	return string(b)
}

func GetMailTemplate(locale, template string) (MailTemplate, error) {

	files := []string{
		common.PluginFile(fmt.Sprintf("translate_email.%s.ini", locale)),
		common.PluginFile(fmt.Sprintf("vendor_email.%s.ini", locale)),
		common.PluginFile("vendor_email.en.ini"),
	}

	htmlFile := common.PluginFile(fmt.Sprintf("email_%s.%s.html", template, locale))

	iftest := func(msg ...interface{}) {
		if MailTest {
			log.Println(msg...)
		}
	}

	if MailTest {
		// when run from le-cp, os.arg[0] is just le-cp, no path included
		// so common.PluginFile doesn't work
		if exeFolder, err := osext.ExecutableFolder(); err == nil {
			for i, f := range files {
				files[i] = filepath.Join(exeFolder, f)
			}
		}
	}

	for i := 0; i < len(files); i++ {
		f := files[i]
		// try check it exists/load the file
		cfg, err := ini.Load(f)
		if err != nil {
			if !os.IsNotExist(err) {
				iftest("Error loading email ini file:", f, err)
			}
			continue
		}
		iftest("Loaded:", f)
		subjectKey := template + "_subject"
		bodyKey := template + "_body"
		section := cfg.Section("")
		// check if it has the keys for the subject/body
		if !section.HasKey(subjectKey) || !section.HasKey(bodyKey) {
			iftest("No section ", subjectKey, " or ", bodyKey, " in email ini file:", f)
			continue
		}
		return MailTemplate{
			Subject: section.Key(subjectKey).String(),
			Body:    section.Key(bodyKey).String(),
			Html:    readAll(htmlFile),
		}, nil
	}

	return MailTemplate{}, errors.New("Unable to find email translation file for: " + locale + ", " + template)
}
