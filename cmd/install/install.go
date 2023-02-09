package install

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common"

	"github.com/fatih/color"
	"github.com/letsencrypt-cpanel/cpanelgo/whm"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/daemon"
	"github.com/kardianos/service"
)

var okPrint = color.New(color.Bold, color.FgGreen).PrintlnFunc()
var warnPrint = color.New(color.Bold, color.FgYellow).PrintlnFunc()

var failPrint = func(args ...interface{}) {
	color.New(color.Bold, color.FgRed).Println(args...)
	os.Exit(1)
}

func run(arg ...string) (int, error) {
	c := exec.Command(arg[0], arg[1:]...)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Run(); err != nil {
		fmt.Println("-----------------------------------")
		fmt.Println("ERROR:", err)
		fmt.Println("-----------------------------------")
		fmt.Println(out.String())
		fmt.Println("-----------------------------------")
		if e2, ok := err.(*exec.ExitError); ok {
			if s, ok := e2.Sys().(syscall.WaitStatus); ok {
				return int(s.ExitStatus()), nil
			}
		}
		return 0, err
	}
	return 0, nil
}

func copyFile(source, dest string, mode os.FileMode) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()
	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}
	return os.Chmod(dest, mode)
}

func installThemeSymlink(theme string) error {
	themeDir := filepath.Join("/usr/local/cpanel/base/frontend/", theme)

	// If the theme doesn't exist, we we don't need to install to it.
	if !common.FileExists(themeDir) {
		return nil
	}

	themePluginDir := filepath.Join(themeDir, "letsencrypt")
	fi, err := os.Lstat(themePluginDir)

	// If the path already exists, we need to remove it before symlinking.
	if err == nil {
		// If it's a symlink, we can just remove it
		if fi.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(themePluginDir)
		} else {
			// Otherwise, rename it
			_ = os.Rename(
				themePluginDir,
				fmt.Sprintf("%s.old.%d", themePluginDir, time.Now().Unix()))
		}
	}

	return os.Symlink(common.ExecDir, themePluginDir)
}

func copyPlugin() {
	themes := []string{"jupiter", "paper_lantern"}
	for _, theme := range themes {
		if err := installThemeSymlink(theme); err != nil {
			warnPrint("Failed to install to theme", theme, err)
		}
	}

	// Symlink to each theme
	if err := copyFile("letsencrypt-cpanel-whm.jpg", "/usr/local/cpanel/whostmgr/docroot/addon_plugins/letsencrypt-cpanel-whm.jpg", 0644); err != nil {
		warnPrint("Error copying WHM icon", err)
	}

	// Symlink to the WHM plugin
	err := os.Symlink(common.ExecDir, "/usr/local/cpanel/whostmgr/docroot/cgi/letsencrypt-cpanel")
	if err != nil && !os.IsExist(err) {
		failPrint("Error symlinking WHM plugin", err)
	}

	okPrint("Copied plugin files OK")
}

func installPlugin() {
	// /usr/local/cpanel/scripts/install_plugin .
	themeNames := []string{
		"jupiter",
		"paper_lantern",
	}
	for _, v := range themeNames {
		fmt.Printf("Installing cPanel %s plugin (may take a minute) ...\n", v)
		ret, err := run("/usr/local/cpanel/scripts/install_plugin", "--theme", v, common.ExecDir)
		if err != nil {
			warnPrint("Error installing cpanel plugin", err, "theme:", v)
		}
		if ret != 0 {
			warnPrint("Unknown error installing cpanel plugin (look at stdout), theme:", v)
		}
	}

	okPrint("cPanel Plugin installer succeeded OK")

	ret, err := run("/usr/local/cpanel/bin/register_appconfig",
		filepath.Join(common.ExecDir, "letsencrypt-cpanel-whm.conf"))
	if err != nil {
		warnPrint("Error installing WHM plugin", err)
	}
	if ret != 0 {
		warnPrint("Unknown error installing WHM plugin (look at stdout)")
	}
}

func installInit() {
	svc := &service.Config{
		Name:        "letsencrypt-cpanel",
		DisplayName: "FleetSSL cPanel",
		Description: "The FleetSSL cPanel renewal service",
		Executable:  common.ExecPath,
		Arguments:   []string{"-mode", "daemon"},
	}

	s, err := service.New(nil, svc)
	if err != nil {
		failPrint("Failed to generate new system service", err)
	}

	if err := s.Uninstall(); err != nil {
		warnPrint("Uninstallation of existing service failed (it's OK)")
	}

	if err = s.Install(); err != nil {
		warnPrint("Failed to install system service! If it already exists, this is OK. Otherwise, please contact support", err)
	}

	okPrint("Installed init scripts. ")

	if common.FileExists("/usr/sbin/chkconfig") {
		if err := exec.Command("chkconfig", "letsencrypt-cpanel", "on").Run(); err != nil {
			warnPrint("Failed to enable the service", err)
		}
	}

	if err := exec.Command("service", "letsencrypt-cpanel", "start").Run(); err != nil {
		warnPrint("Failed to start the service", err)
	}
}

func installChkservd() {
	// copy letsencrypt.chkservd to /etc/chkserv.d/letsencrypt
	if err := copyFile("letsencrypt.chkservd", "/etc/chkserv.d/letsencrypt-cpanel", 0644); err != nil {
		warnPrint("Error copying letsencrypt.chkservd", err)
		return
	}

	os.Remove("/etc/chkserv.d/letsencrypt")

	// add line letsencrypt:1 to /etc/chkserv.d/chkservd.conf
	input, err := ioutil.ReadFile("/etc/chkserv.d/chkservd.conf")
	if err != nil {
		warnPrint("Can't open chkservd.conf", err)
		return
	}

	lineInstalled := false
	lines := strings.Split(string(input), "\n")
	for i, line := range lines {
		if strings.Contains(line, "letsencrypt:") || strings.Contains(line, "letsencrypt-cpanel:") {
			lineInstalled = true
			lines[i] = "letsencrypt-cpanel:1"
		}
	}
	if !lineInstalled {
		lines = append(lines, "letsencrypt-cpanel:1")
	}
	// add newline on the end of the output in case a script
	// (ie, cpanel-ccs plugin installer)
	// dumbly appends to the file
	output := strings.Join(lines, "\n") + "\n"
	err = ioutil.WriteFile("/etc/chkserv.d/chkservd.conf", []byte(output), 0644)
	if err != nil {
		warnPrint("Can't write to chkservd.conf", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/scripts/restartsrv_chkservd").Run(); err != nil {
		if err := exec.Command("/usr/local/cpanel/scripts/restartsrv_chkservd").Run(); err != nil {
			warnPrint("Failed to restart chkservd, but will keep going: ", err)
		} else {
			okPrint("Installed chkservd scripts")
		}
	} else {
		okPrint("Installed chkservd scripts")
	}
}

func checkSelfSigned() (bool, error) {
	hn, err := os.Hostname()
	if err != nil {
		return false, err
	}

	resp, err := http.Get(fmt.Sprintf("https://%s:2083", hn))
	if err != nil {
		if strings.Index(err.Error(), "x509: ") >= 0 {
			return true, nil
		} else {
			return false, err
		}
	}
	defer resp.Body.Close()
	return false, nil
}

func installConfig() {
	isSelfSigned, err := checkSelfSigned()
	if err != nil {
		warnPrint("Failed to check host service certificate", err)
		isSelfSigned = true
	}

	if isSelfSigned {
		warnPrint("")
		warnPrint("This server has self-signed service certificates")
		warnPrint("It is not safe to operate this plugin in this circumstance")
		warnPrint("'insecure' is being added to /etc/letsencrypt-cpanel.conf")
		warnPrint("")
		warnPrint("If you wish to generate a Let's Encrypt cert for the server")
		warnPrint("Please read the configuration documentation on our website, at")
		warnPrint("https://cpanel.fleetssl.com/docs/service-certificates/")
		warnPrint("")
	}

	var v daemon.Config
	if common.FileExists(common.ConfigPath) {
		bytes, err := ioutil.ReadFile(common.ConfigPath)
		if err != nil {
			warnPrint("Failed to read existing config file", err)
		}

		if err := json.Unmarshal(bytes, &v); err != nil {
			warnPrint("Failed to unmarshal existing config file. Try deleting it?", err)
		}
	}

	// any changes to config here
	v.Insecure = isSelfSigned

	if err := daemon.WriteConfig(v); err != nil {
		warnPrint("Error writing config", err)
	}

	okPrint("Config written to " + common.ConfigPath)
}

func setCpanelTweaks() {
	s, err := common.ReadApiToken()
	if err != nil {
		failPrint(err)
		return
	}

	whmcl := whm.NewWhmApiAccessHashTotp("127.0.0.1", "root", s, true, common.ReadTotpSecret())

	if _, err := whmcl.SetTweakSetting("allowcpsslinstall", "", "1"); err != nil {
		warnPrint("Error setting tweak setting 'allowcpsslinstall'", err)
		return
	}

	okPrint("Set cpanel tweak settings")
}

func installApachePreinclude() {
	tokenStart := "### BEGIN AUTOGENERATED BY LETS ENCRYPT FOR CPANEL PLUGIN ###"
	tokenEnd := "### END AUTOGENERATED BY LETS ENCRYPT FOR CPANEL PLUGIN ###"
	contents := `<Location /.well-known/acme-challenge>
        Order deny,allow
        Allow from all
        Satisfy any
</Location>`

	fullContents := []byte("\n" + tokenStart + "\n" + contents + "\n" + tokenEnd + "\n")

	// open the file
	fd, err := os.OpenFile("/usr/local/apache/conf/includes/pre_virtualhost_global.conf", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		warnPrint("Error opening apache pre virtual host include, ", err)
		return
	}
	defer fd.Close()

	// lock it (syscall.Close will unlock)
	err = syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		warnPrint("Error locking apache pre virtual host global include, ", err)
		return
	}

	// read whole file
	in, err := ioutil.ReadAll(fd)
	if err != nil {
		warnPrint("Error reading pre virtual host global include", err)
		return
	}

	out := []byte{}

	if len(in) == 0 {
		// if nothing was read, output is just
		out = append(out, fullContents...)
	} else {
		// replace all the contents with new
		r := regexp.MustCompile("(?ms)" + tokenStart + "(.*)" + tokenEnd)

		// if block isnt in file, append new block
		if r.Find(in) == nil {
			out = append(in, fullContents...)
		} else {
			// otherwise replace contents with new
			out = r.ReplaceAll(in, fullContents)
		}
	}

	if _, err := fd.Seek(0, 0); err != nil {
		warnPrint("Error seeking apache pre virtual host global include, ", err)
		return
	}

	if err := fd.Truncate(0); err != nil {
		warnPrint("Failed to truncate apache pre virtual host include", err)
		return
	}

	if _, err := fd.Write(out); err != nil {
		warnPrint("Error writing apache pre virtual host global include, ", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/scripts/restartsrv_apache").Run(); err != nil {
		if err := exec.Command("/usr/local/cpanel/scripts/restartsrv_apache").Run(); err != nil {
			warnPrint("Added apache pre virtualhost global include installed, but failed to restart apache: ", err)
			return
		}
	}

	okPrint("Added apache pre virtualhost global include")
}

func updateRepoToCDN() {
	if err := filepath.Walk("/etc/yum.repos.d", func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		sBuf := string(buf)
		if strings.Contains(sBuf, "baseurl=https://letsencrypt-for-cpanel.com/repo") {
			sBuf = strings.ReplaceAll(sBuf, "baseurl=https://letsencrypt-for-cpanel.com/repo", "baseurl=https://r.cpanel.fleetssl.com")
		}
		if err := ioutil.WriteFile(path, []byte(sBuf), fi.Mode().Perm()); err != nil {
			warnPrint("Failed to update repo: ", path, err)
		}
		return nil
	}); err != nil {
		warnPrint("Updating yum repo failed: ", err)
	}
}

func Run() {
	// high prio below this line, in ascending order of likelyhood to fail
	installConfig()
	installInit()
	copyPlugin()
	installPlugin()
	// low prio below this line
	installChkservd()
	installApachePreinclude()
	setCpanelTweaks()
	updateRepoToCDN()

	okPrint("\n--- Installation complete ---")
	okPrint("The plugin should now be available in the cPanel feature manager")
}
