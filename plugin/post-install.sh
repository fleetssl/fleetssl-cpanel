#!/usr/bin/env bash

chmod +x /opt/fleetssl-cpanel/get_proxy_names

cd /opt/fleetssl-cpanel && ./letsencrypt.live.cgi -mode install

# symlink for easy access
ln -sf /opt/fleetssl-cpanel/letsencrypt.live.cgi /usr/local/bin/le-cp

# we need to restart apache to load in the new autossl exclusion urls the first time
NEEDS_APACHE_RESTART=0
if [ ! -e /var/cpanel/perl/Cpanel/SSL/Auto/Provider/FleetSSLProvider.pm ]; then
	echo "Will rebuild conf and restart Apache to reload AutoSSL DCV URLs"
	NEEDS_APACHE_RESTART=1
fi

# symlink autossl provider
mkdir -p /var/cpanel/perl/Cpanel/SSL/Auto/Provider/
ln -sf /opt/fleetssl-cpanel/FleetSSLProvider.pm /var/cpanel/perl/Cpanel/SSL/Auto/Provider/FleetSSLProvider.pm

# rebuild httpconf to update new autossl provider and restart apache
if [ $NEEDS_APACHE_RESTART -eq "1" ]; then
	echo "Rebuilding Apache conf and restarting now ..."
	/scripts/rebuildhttpdconf && /scripts/restartsrv_httpd > /dev/null
fi

# Run installer script fix asynchronously so that we can automatically fix the prerm issue.
chmod +x /opt/fleetssl-cpanel/fix_fleetssl_cpanel_0.19.5-upgrade.sh
nohup /opt/fleetssl-cpanel/fix_fleetssl_cpanel_0.19.5-upgrade.sh 2>&1 >/dev/null &
