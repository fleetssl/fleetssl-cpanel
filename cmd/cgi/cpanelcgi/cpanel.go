package cpanelcgi

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"
	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon/client"

	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

type ActionData struct {
	Cpanel         cpanel.CpanelApi
	Resp           http.ResponseWriter
	Req            *http.Request
	NVData         *common.NVDataAccount
	DomainList     common.DomainList
	Theme          string
	AutoSSLEnabled bool
	CustomDomains  bool
}

type ActionFunc func(data ActionData) ErrorList
type ErrorList []interface{}

func (el ErrorList) GatherErrors() []string {
	out := make([]string, len(el))
	for _, el := range el {
		out = append(out, fmt.Sprintf("%v", el))
	}
	return out
}

var translateFuncs = template.FuncMap{
	"TS": func(in string) template.HTML {
		return template.HTML(TS(in))
	},
	"TF": func(in string, a ...interface{}) template.HTML {
		return template.HTML(TF(in, a...))
	},
}

func ServeCpanelCgi(w http.ResponseWriter, r *http.Request) {

	// create the new cpanel connection using the env unix socket
	cl, err := cpanel.NewLiveApi("unix", os.Getenv("CPANEL_CONNECT_SOCKET"))
	if err != nil {
		serveFatal(w, "Error connecting to cPanel API", err) // no locale yet, don't TS()
		return
	}
	defer cl.Close()

	// data object
	data := ActionData{
		Cpanel: cl,
		Resp:   w,
		Req:    r,
	}

	// first thing, get the users local to allow translations
	l, err := cl.GetLocaleAttributes()
	if err != nil {
		serveFatal(w, "Unable to fetch locale attributes", err) // no locale yet, don't TS()
		return
	}
	SetLocale(l.Data.Locale)

	// get the theme
	theme, err := cl.GetTheme()
	if err != nil {
		serveFatal(w, TS("Error getting theme"), err)
		return
	}
	data.Theme = theme.Theme // set theme in data

	featureEnabled, err := isFeatureEnabled(cl, data.Theme)
	if !featureEnabled {
		serveError(data, TS("This functionality is disabled for this hosting package."), err)
	}

	// get the users account stored nvdata
	account, err := common.GetAndParseNVData(cl)
	if err != nil {
		serveError(data, TS("Error parsing user nvdata"), err)
		return
	}

	data.NVData = account // set nvdata in data

	domains, err := common.GetDomainList(cl)
	if err != nil {
		serveError(data, TS("Error getting user domains"), err)
	}
	data.DomainList = domains // set domainlist in data

	// add the custom/extra domains (if enabled)
	customDomains, err := client.GetConfig("customdomains")
	if err != nil {
		log.WithError(err).Println("Error fetching custom domains")
		customDomains = "false"
	}
	if customDomains == "true" {
		for name, entry := range domains {
			zone, err := cl.FetchZone(name, "A,AAAA,CNAME")
			if err != nil {
				continue
			}
			if len(zone.Data) == 0 {
				continue
			}
			if len(zone.Data[0].Records) == 0 {
				continue
			}
			for _, record := range zone.Data[0].Records {
				subentry := entry
				subentry.Domain = strings.TrimSuffix(record.Name, ".")
				subentry.DomainType = "Custom"

				// For now, only present mail in the frontend
				if subentry.Domain != ("mail." + name) {
					continue
				}

				domains.AddDomainEntry(subentry)
			}
		}
	}
	data.CustomDomains = (customDomains == "true") // set customdomains in data

	// add if autossl is enabled
	autoSslEnabled, err := client.GetConfig("autosslenabled")
	if err != nil {
		log.WithError(err).Println("Error fetching custom domains")
		autoSslEnabled = "false"
	}
	data.AutoSSLEnabled = (autoSslEnabled == "true")

	action := r.FormValue("action")
	actionFunc, ok := actionList[action]
	if !ok {
		// default to home if no action found
		actionFunc = actionList[""]
	}

	errList := actionFunc(data)
	if errList != nil && len(errList) > 0 {
		serveError(data, errList...)
	}
}

var actionList = map[string]ActionFunc{
	"issue":        actionIssue,
	"remove":       actionRemove,
	"remove-reuse": actionRemoveReuse,
	"view":         actionView,
	"reinstall":    actionReinstall,
	"settings":     actionSettings,
	"":             actionHome,
}

// This function will print errors to responseWriter and should be used only before the cpanel api is initialised
// Otherwise use serveError
func serveFatal(w http.ResponseWriter, errs ...interface{}) {
	fmt.Fprintln(w, TS("A fatal error occurred."))
	for _, e := range errs {
		fmt.Fprintln(w, " - ", e)
	}
}

// This function isn't for actual errors, just ones to be displayed to the end user
func serveError(data ActionData, errs ...interface{}) {
	serveTemplate(data, "error.html", errs)
}

func serveTemplate(data ActionData, filename string, templateData interface{}) {

	// include custom dom/branding for default themes before the header
	pageDom, _ := data.Cpanel.GetDom(TS("Let's Encrypt&trade; SSL"))
	if pageDom.Data.Header != "" {
		fmt.Fprint(data.Resp, template.HTML(pageDom.Data.Header))
	} else {
		data.Cpanel.SetVar("dprefix", "../") // this fixes the home button at the top
		data.Cpanel.SetVar("hidehelp", "1")  // hides the useless help button
		brandingHeader, _ := data.Cpanel.BrandingInclude("stdheader.html")
		if brandingHeader.Data.Result != "" {
			fmt.Fprint(data.Resp, brandingHeader.Data.Result)
		}
	}

	// include any custom header template
	headerTpl, err := common.LoadTemplate("custom_theme_"+data.Theme+"_header.html", translateFuncs)
	if err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("file", "custom_theme_"+data.Theme+"_header.html").Println("Error loading custom theme header")
		}
		// before attempting to include the vendor included one
		headerTpl, err = common.LoadTemplate("vendor_theme_"+data.Theme+"_header.html", translateFuncs)
		if err != nil && !os.IsNotExist(err) {
			serveFatal(data.Resp, TS("Error loading header template"), err)
			return
		}
	}

	// and execute the loaded header template
	if headerTpl != nil {
		if err := headerTpl.Execute(data.Resp, templateData); err != nil {
			serveFatal(data.Resp, TS("Error serving header template"), err)
			return
		}
	}

	fmt.Fprint(data.Resp, "<!-- LE4CP theme:", data.Theme, " -->")

	// attempt to load the custom version of the template filename
	tpl, err := common.LoadTemplate("custom_"+filename, translateFuncs)
	// without path it looks for stuff in /usr/local/cpanel/base
	// but we need /usr/local/cpanel/base/frontend/jupiter/letsencrypt
	// todo: is this the best way to do this?
	if err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("file", "custom_"+filename).Println("Error loading custom template")
		}
		// attempt to load the vendor version of the template filename
		tpl, err = common.LoadTemplate("vendor_"+filename, translateFuncs)
		if err != nil {
			serveFatal(data.Resp, TS("Error parsing template"), filename, err)
			return
		}
	}

	// execute the loaded page template
	if err := tpl.Execute(data.Resp, templateData); err != nil {
		serveFatal(data.Resp, TS("Error executing template"), err)
		return
	}

	// attempt to load custom footer template
	footerTpl, err := common.LoadTemplate("custom_theme_"+data.Theme+"_footer.html", translateFuncs)
	if err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("file", "custom_theme_"+data.Theme+"_footer.html").Println("Error loading custom theme footer")
		}
		footerTpl, err = common.LoadTemplate("vendor_theme_"+data.Theme+"_footer.html", translateFuncs)
		if err != nil && !os.IsNotExist(err) {
			serveFatal(data.Resp, TS("Error loading footer template"), err)
			return
		}
	}

	// and execute the loaded footer template
	if footerTpl != nil {
		if err := footerTpl.Execute(data.Resp, templateData); err != nil {
			serveFatal(data.Resp, TS("Error serving footer template"), err)
			return
		}
	}

	// include custom dom/branding for default themes after the footer
	if pageDom.Data.Footer != "" {
		fmt.Fprint(data.Resp, template.HTML(pageDom.Data.Footer))
	} else {
		brandingFooter, _ := data.Cpanel.BrandingInclude("stdfooter.html")
		if brandingFooter.Data.Result != "" {
			fmt.Fprint(data.Resp, brandingFooter.Data.Result)
		}
	}
}

func serveResult(data ActionData, results ...string) {
	serveTemplate(data, "result.html", results)
}

func isFeatureEnabled(cp cpanel.CpanelApi, theme string) (bool, error) {
	featureName := "letsencrypt-cpanel"
	if theme == "x3" {
		featureName = "letsencrypt"
	}
	if message, err := cp.HasFeature(featureName); err != nil {
		// Workaround for broken cPanel 64
		// and workaround for broken cPanel 102
		if !strings.Contains(err.Error(), "/var/cpanel/licenseid_credentials.json") &&
			!strings.Contains(err.Error(), "open(/etc/trueuserdomains): Permission denied") {
			return false, fmt.Errorf("Unable to fetch feature (%s) status: %s", featureName, err.Error())
		}
	} else if message != "" {
		// the message only exists when the feature is disabled
		// when it's enabled, it will be an empty string
		// eg: "The feature “chat” exists but is not enabled."
		return false, errors.New(message)
	}
	return true, nil
}
