#!/usr/bin/env bash

okPrint() {
	echo -e "\e[32m${1}\e[0m"
}

warnPrint() {
	echo -e "\e[33m${1}\e[0m"
}

failPrint() {
	echo -e "\e[91m${1}\e[0m"
	exit 1
}

fileExists() {
	if [ -s "$1" ]; then
		return 0 # true
	else
		return 1 # false
	fi
}

daemonRunning() {
    pidof letsencrypt.live.cgi > /dev/null
    return $?
}

checkRoot() {
	if (( EUID != 0 )); then
		failPrint "Please run installer as root"
	fi
	okPrint "Running installer as root"
}

checkOsVersion() {
    if [ "$FLEETSSL_SKIP_OS_CHECK" = "y" ]; then
        return
    fi

    if ! fileExists "/etc/os-release"; then
        # CloudLinux is missing /etc/os-release. Let's silently ignore it.
        return
    fi
    . /etc/os-release

    # Any non-EOL RHEL variant is okay
    if fileExists "/etc/redhat-release" && [ $(echo "$VERSION_ID >= 7" | bc -l) = 1 ]; then
        okPrint "RHEL-like OS version OK!"
        return
    fi

    # Ubuntu 20.04 is okay
    if [ \( "$ID" = "ubuntu" -a "$VERSION_ID" = "20.04" \) ]; then
        okPrint "Ubuntu OS version OK!"
        return
    fi

    failPrint "Unsupported operating system $ID ($VERSION_ID). Set the env variable FLEETSSL_SKIP_OS_CHECK=y to force installation."
}

checkCpanelVersion() {
    if ! fileExists "/usr/local/cpanel/cpanel"; then
		failPrint "Cannot find cPanel installed"
    fi
}

stopService() {
    service letsencrypt-cpanel stop > /dev/null
    if daemonRunning; then
        warnPrint "Daemon service not stopped successfully, attempting manual shutdown"
        killall -TERM letsencrypt.live.cgi
        sleep 5s
        if daemonRunning; then
            warnPrint "Manual shutdown not successful, killing process"
            killall -9 letsencrypt.live.cgi
        fi
    fi
    okPrint "FleetSSL cPanel service daemon stopped"
}

okPrint "*** By running this installer, you indicate that you have read the end-user\n licence agreement (https://cpanel.fleetssl.com/eula) and agree to all of its terms, as stated. ***\n"

checkRoot
checkOsVersion
checkCpanelVersion

stopService
