#!/usr/bin/env bash

if [ -n "$RPM_INSTALL_PREFIX" ]; then
  if [ "$1" != "0" ]; then
    echo "Not uninstalling as it is an RPM upgrade"
    exit 0
  fi
else
  if [ "$1" != "remove" ]; then
    echo "Not uninstalling as it is a Debian upgrade"
    exit 0
  fi
fi

PLUGIN_PATH=/usr/local/cpanel/base/frontend/paper_lantern/letsencrypt
JUPITER_PLUGIN_PATH=/usr/local/cpanel/base/frontend/jupiter/letsencrypt
WHM_PLUGIN_PATH=/usr/local/cpanel/whostmgr/docroot/cgi/letsencrypt-cpanel

service letsencrypt-cpanel stop 
rm -f /etc/init.d/letsencrypt-cpanel /etc/systemd/system/letsencrypt-cpanel.service
rm -f /etc/systemd/system/multi-user.target.wants/letsencrypt-cpanel.service

cd $PLUGIN_PATH && /usr/local/cpanel/scripts/uninstall_plugin .
cd $JUPITER_PLUGIN_PATH && /usr/local/cpanel/scripts/uninstall_plugin --theme jupiter .
cd $WHM_PLUGIN_PATH && /usr/local/cpanel/bin/unregister_appconfig letsencrypt-cpanel-whm.conf

rm -f /var/cpanel/perl/Cpanel/SSL/Auto/Provider/FleetSSLProvider.pm

rm -rf $PLUGIN_PATH $JUPITER_PLUGIN_PATH \
  /usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_letsencrypt-cpanel.conf \
  /usr/local/cpanel/base/frontend/paper_lantern/dynamicui/dynamicui_letsencrypt-cpanel.conf

rm -f /var/lib/letsencrypt-cpanel.db

rm -rf $WHM_PLUGIN_PATH /usr/local/cpanel/whostmgr/docroot/addon_plugins/letsencrypt-cpanel-whm.jpg

rm -f /etc/chkserv.d/letsencrypt-cpanel
sed -i '/letsencrypt:/d' /etc/chkserv.d/chkservd.conf
sed -i '/letsencrypt-cpanel:/d' /etc/chkserv.d/chkservd.conf
/scripts/restartsrv_chkservd

rm -rf /opt/fleetssl-cpanel

echo '#########################################'
echo '#         Uninstall completed           #'
echo '#########################################'
echo 'No account data was removed and is still accessible in users home/.cpanel/nvdata/letsencrypt-cpanel'
echo 'The following files were not removed and will need to be removed manually:'
echo ' /etc/letsencrypt-cpanel.conf'
echo ' /etc/letsencrypt-cpanel.licence'
echo '#########################################'
