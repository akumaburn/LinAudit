#!/bin/sh
# Download the offline databases used by the network panel:
#   1. IP -> country  (family geo-whois-asn-country) -> ipv4.csv / ipv6.csv
#   2. IP -> ASN/org  (family asn)                   -> asn-ipv4.csv / asn-ipv6.csv
# Source: sapics/ip-location-db (CC BY 4.0; country by NRO, ASN by RouteViews/
# DB-IP/NRO). All lookups are offline against these files; observed IPs never
# leave the machine. The ASN/org DB powers the "known network owner" classifier
# (corp / cloud / cdn / gov / telecom). Re-run periodically to refresh (the
# upstream data is updated daily).
#
# Usage: sudo sh data/fetch-geoip.sh [DEST]   (DEST default: /usr/local/share/linaudit/geoip)
set -eu
DEST="${1:-/usr/local/share/linaudit/geoip}"
CC_BASE="https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country"
ASN_BASE="https://raw.githubusercontent.com/sapics/ip-location-db/main/asn"

install -d -m755 "$DEST"

# IP -> country
curl -fsSL -o "$DEST/ipv4.csv" "$CC_BASE/geo-whois-asn-country-ipv4.csv"
curl -fsSL -o "$DEST/ipv6.csv" "$CC_BASE/geo-whois-asn-country-ipv6.csv"
chmod 644 "$DEST/ipv4.csv" "$DEST/ipv6.csv"

# IP -> ASN / organization
curl -fsSL -o "$DEST/asn-ipv4.csv" "$ASN_BASE/asn-ipv4.csv"
curl -fsSL -o "$DEST/asn-ipv6.csv" "$ASN_BASE/asn-ipv6.csv"
chmod 644 "$DEST/asn-ipv4.csv" "$DEST/asn-ipv6.csv"

echo "GeoIP country + ASN/org DBs installed to $DEST"
ls -l "$DEST"
