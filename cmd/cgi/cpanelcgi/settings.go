package cpanelcgi

import "bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"

func actionSettings(data ActionData) ErrorList {
	if data.Req.Method == "POST" {
		data.NVData.DisableMail = (data.Req.FormValue("DisableMail") != "")

		_, err := data.Cpanel.SetNVData(common.NVDatastoreName, data.NVData)
		if err != nil {
			return ErrorList{TS("Unable to save settings"), err}
		}

		serveResult(data, TS("Settings saved successfully"))
		return nil
	}

	serveTemplate(data, "settings.html", struct {
		DisableMail bool
	}{
		DisableMail: data.NVData.DisableMail,
	})

	return nil
}
