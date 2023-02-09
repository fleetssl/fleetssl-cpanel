package Cpanel::SSL::Auto::Provider::FleetSSLProvider;

# This module exists purely for the purpose of injecting the DCV_PATH
# into the proxy subdomain virtual host generated by cPanel.
# It is NOT for use in WHM AutoSSL.
# https://cpanel.fleetssl.com
 
use strict;
use warnings;
 
use parent qw( Cpanel::SSL::Auto::Provider );
 
sub DAYS_TO_REPLACE { return 1; }
sub MAX_DOMAINS_PER_CERTIFICATE { return 0; }
sub DISPLAY_NAME { return 'FleetSSL (internal use only, don\'t use in WHM AutoSSL)'; }
sub CERTIFICATE_IS_FROM_HERE { return 0; }
sub REQUEST_URI_DCV_PATH { return  '^/\\.well-known/acme-challenge/.+$'; }

sub renew_ssl_for_vhosts { return; }

1;

