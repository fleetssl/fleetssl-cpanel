package common

import (
	"html/template"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func LoadTemplate(filename string, extraFuncs template.FuncMap) (*template.Template, error) {
	baseFuncs := template.FuncMap{
		"timeToString": func(t int64) string {
			if t == 0 {
				return "-"
			}
			return time.Unix(t, 0).Format("02 Jan 2006")
		},
		"stimeToString": func(s string) string {
			t, _ := strconv.ParseInt(s, 10, 64)
			if t == 0 {
				return "-"
			}
			return time.Unix(t, 0).Format("02 Jan 2006")
		},
		"hasPrefix": func(s string, prefix ...string) bool {
			for _, pref := range prefix {
				if strings.HasPrefix(s, pref) {
					return true
				}
			}
			return false
		},
		"hasSuffix": func(s string, suffix ...string) bool {
			for _, suff := range suffix {
				if strings.HasSuffix(s, suff) {
					return true
				}
			}
			return false
		},
		"contains": func(s string, needles ...string) bool {
			for _, needle := range needles {
				if strings.Contains(s, needle) {
					return true
				}
			}
			return false
		},
		"domainHasPrefixes": func(domain, root string, prefixes ...string) bool {
			for _, p := range prefixes {
				if domain == p+root {
					return true
				}
			}
			return false
		},
		"strJoin": func(sep string, tojoin []string) string {
			return strings.Join(tojoin, sep)
		},
	}

	if extraFuncs != nil {
		for n, f := range extraFuncs {
			baseFuncs[n] = f
		}
	}

	tpl, err := template.New(filepath.Base(filename)).Funcs(baseFuncs).ParseFiles(PluginFile(filename))
	return tpl, err
}
