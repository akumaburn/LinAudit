#!/bin/sh
# Download the offline IP-to-country database used by the network panel.
# Source: sapics/ip-location-db, family geo-whois-asn-country (CC BY 4.0, by NRO;
# ~97% country-code accuracy). All lookups are offline against these files; observed
# IPs never leave the machine. Re-run periodically to refresh (data is daily-updated).
#
# Usage: sudo sh data/fetch-geoip.sh [DEST]   (DEST default: /usr/local/share/linaudit/geoip)
set -eu
DEST="${1:-/usr/local/share/linaudit/geoip}"
BASE="https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country"

install -d -m755 "$DEST"
curl -fsSL -o "$DEST/ipv4.csv" "$BASE/geo-whois-asn-country-ipv4.csv"
curl -fsSL -o "$DEST/ipv6.csv" "$BASE/geo-whois-asn-country-ipv6.csv"
chmod 644 "$DEST/ipv4.csv" "$DEST/ipv6.csv"

echo "GeoIP country DB installed to $DEST"
ls -l "$DEST"
