#!/usr/bin/env bash

sleep 60

# If the le-cp symlink is valid, nothing to fix.
if [ -f /usr/local/bin/le-cp ]; then
    exit 0
fi

# If the RPM is not installed, nothing to fix.
if ! rpm -q --quiet letsencrypt-cpanel; then
    exit 0
fi

yum -yq reinstall letsencrypt-cpanel