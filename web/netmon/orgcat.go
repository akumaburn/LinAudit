package netmon

// orgcat.go classifies an ASN organization name into a coarse network category
// used for the dashboard's "known vs unknown" colour coding. It is deliberately
// heuristic and offline:
//
//   - A small curated set of government/military ASNs (govASNs) is the highest-
//     confidence signal, for operators whose AS-name does not read as government.
//   - Government phrases/tokens (isGov) catch clearly-named public bodies.
//   - A provider table (orgRules) maps well-known operators to corp/cloud/cdn/
//     telecom.
//   - Anything with a resolved org but no match is "other"; an unresolved IP
//     (no ASN row) is left uncategorised by the caller ("unknown").
//
// Government detection in particular is best-effort: AS-names rarely say
// "government" cleanly, so some public networks are missed and the occasional
// edge case is mislabelled. The matcher is intentionally conservative (word
// boundaries for short tokens; phrases, not bare words like FEDERAL/ARMY/NAVY)
// to avoid known false positives (Federal Express, Salvation Army, Navy Federal
// Credit Union, Governors State University). See orgcat_test.go.

import "strings"

// Category values surfaced on each connection (connRow.Cat) and tallied in the
// snapshot's categories map. "" is never produced by categorize for a resolved
// org; the caller uses "unknown" for IPs with no ASN match.
const (
	catCorp    = "corp"    // big tech / enterprise (Microsoft, Apple, Google, ...)
	catCloud   = "cloud"   // cloud / hosting / VPS (AWS, Azure*, GCP*, Hetzner, ...)
	catCDN     = "cdn"     // content delivery / edge (Cloudflare, Akamai, Fastly, ...)
	catGov     = "gov"     // government / military (best-effort)
	catTelecom = "telecom" // consumer ISPs / carriers (Comcast, Vodafone, ...)
	catOther   = "other"   // resolved org, no category match
)

// govASNs is a curated, high-confidence set of government/military ASNs whose
// AS-name alone would not be flagged by the phrase heuristic. Verified against
// the ip-location-db asn dataset. Extend as needed.
var govASNs = map[uint32]bool{
	721:   true, // DoD Network Information Center
	27064: true, // DoD Network Information Center (DNIC)
	1733:  true, // United States Department of Defense (DoD)
	297:   true, // National Aeronautics and Space Administration (NASA)
}

// govPhrases are uppercased substrings that strongly indicate a government or
// military operator. Multi-word where possible to limit false positives.
var govPhrases = []string{
	"DEPARTMENT OF", "MINISTRY OF", "MINISTRY FOR", "GOVERNMENT",
	"CITY OF ", "COUNTY OF ", "STATE OF ", "COMMONWEALTH OF",
	"PROVINCE OF", "MUNICIPALITY", "MUNICIPAL ", "NATIONAL GUARD",
	"DEFENSE INFORMATION", "DEFENCE INFORMATION", "AERONAUTICS AND SPACE",
	"PARLIAMENT", "EMBASSY", "FEDERAL BUREAU", "FEDERAL MINISTRY",
	"FEDERAL GOVERNMENT", "MILITARY", "AIR FORCE", "SPACE FORCE",
	"MARINE CORPS", "COAST GUARD", "ARMY CORPS", "US ARMY", "U.S. ARMY",
	"UNITED STATES ARMY", "US NAVY", "U.S. NAVY", "UNITED STATES NAVY",
	"DEPARTMENT OF THE NAVY", "DEPARTMENT OF THE ARMY", ".GOV", ".MIL",
}

// govTokens are distinctive acronyms matched only on word boundaries. Short,
// ambiguous tokens (ARMY, NAVY, MIL, FEDERAL) are intentionally excluded here
// and handled via the phrases above to avoid false positives.
var govTokens = []string{"GOV", "DOD", "USAF", "NASA", "NOAA", "USGS", "USACE", "FEMA"}

// orgRule maps an uppercased AS-name marker to a category. When word is true the
// marker must match on word boundaries (for short markers that could otherwise
// appear inside an unrelated word).
type orgRule struct {
	pat  string
	cat  string
	word bool
}

// orgRules is checked in order; the first match wins. Government is resolved
// before this table (see categorize) so municipal names like "County of Orange"
// are not captured by the telecom "ORANGE" rule.
var orgRules = []orgRule{
	// CDN / edge
	{"CLOUDFLARE", catCDN, false}, {"AKAMAI", catCDN, false}, {"FASTLY", catCDN, false},
	{"EDGECAST", catCDN, false}, {"EDGIO", catCDN, false}, {"LIMELIGHT", catCDN, false},
	{"STACKPATH", catCDN, false}, {"INCAPSULA", catCDN, false}, {"IMPERVA", catCDN, false},
	{"CDN77", catCDN, false}, {"GCORE", catCDN, false}, {"BUNNYWAY", catCDN, false},
	// Big tech / corporate
	{"MICROSOFT", catCorp, false}, {"APPLE", catCorp, true}, {"GOOGLE", catCorp, false},
	{"META PLATFORMS", catCorp, false}, {"FACEBOOK", catCorp, false}, {"NETFLIX", catCorp, false},
	{"GITHUB", catCorp, false}, {"DROPBOX", catCorp, false}, {"TWITTER", catCorp, false},
	{"X CORP", catCorp, true}, {"LINKEDIN", catCorp, false}, {"PAYPAL", catCorp, false},
	{"ADOBE", catCorp, false}, {"SALESFORCE", catCorp, false}, {"NVIDIA", catCorp, false},
	{"CISCO", catCorp, true}, {"SPOTIFY", catCorp, false}, {"IBM", catCorp, true},
	{"INTEL", catCorp, true}, {"UBER", catCorp, true},
	// Cloud / hosting / VPS
	{"AMAZON", catCloud, true}, {"AWS", catCloud, true}, {"DIGITALOCEAN", catCloud, false},
	{"LINODE", catCloud, false}, {"VULTR", catCloud, false}, {"CHOOPA", catCloud, false},
	{"HETZNER", catCloud, false}, {"OVH", catCloud, false}, {"SCALEWAY", catCloud, false},
	{"CONTABO", catCloud, false}, {"LEASEWEB", catCloud, false}, {"ALIBABA", catCloud, false},
	{"ALICLOUD", catCloud, false}, {"ALIYUN", catCloud, false}, {"TENCENT", catCloud, false},
	{"HUAWEI", catCloud, false}, {"ORACLE", catCloud, true}, {"GODADDY", catCloud, false},
	{"DREAMHOST", catCloud, false}, {"BLUEHOST", catCloud, false}, {"HOSTGATOR", catCloud, false},
	{"NAMECHEAP", catCloud, false}, {"RACKSPACE", catCloud, false}, {"UPCLOUD", catCloud, false},
	{"KAMATERA", catCloud, false}, {"NETCUP", catCloud, false},
	// Telecom / consumer ISP / carrier
	{"COMCAST", catTelecom, false}, {"VERIZON", catTelecom, false}, {"AT&T", catTelecom, false},
	{"T-MOBILE", catTelecom, false}, {"SPRINT", catTelecom, true}, {"CHARTER", catTelecom, true},
	{"SPECTRUM", catTelecom, false}, {"COX COMMUNICATIONS", catTelecom, false},
	{"CENTURYLINK", catTelecom, false}, {"LUMEN", catTelecom, false}, {"LEVEL 3 ", catTelecom, false},
	{"DEUTSCHE TELEKOM", catTelecom, false}, {"VODAFONE", catTelecom, false}, {"ORANGE", catTelecom, false},
	{"TELEFONICA", catTelecom, false}, {"CHINA TELECOM", catTelecom, false}, {"CHINA UNICOM", catTelecom, false},
	{"CHINA MOBILE", catTelecom, false}, {"RELIANCE JIO", catTelecom, false}, {"BHARTI AIRTEL", catTelecom, false},
	{"KDDI", catTelecom, false}, {"ROGERS COMMUNICATIONS", catTelecom, false}, {"BELL CANADA", catTelecom, false},
	{"TELUS", catTelecom, false}, {"NTT", catTelecom, true}, {"BT", catTelecom, true},
}

// categorize returns the network category for a resolved (asn, org). It returns
// catOther when org is non-empty but matches nothing. Government is resolved
// first (curated ASN, then name heuristic) so it wins over provider rules.
func categorize(asn uint32, org string) string {
	if org == "" {
		return catOther
	}
	if govASNs[asn] {
		return catGov
	}
	up := strings.ToUpper(org)
	if isGov(up) {
		return catGov
	}
	for _, r := range orgRules {
		if r.word {
			if hasToken(up, r.pat) {
				return r.cat
			}
		} else if strings.Contains(up, r.pat) {
			return r.cat
		}
	}
	return catOther
}

// isGov reports whether an uppercased org name looks governmental/military.
func isGov(up string) bool {
	for _, p := range govPhrases {
		if strings.Contains(up, p) {
			return true
		}
	}
	for _, t := range govTokens {
		if hasToken(up, t) {
			return true
		}
	}
	return false
}

// hasToken reports whether tok occurs in s bounded by non-alphanumeric
// characters on both sides. Both s and tok must already be uppercased.
func hasToken(s, tok string) bool {
	if tok == "" {
		return false
	}
	for start := 0; start < len(s); {
		i := strings.Index(s[start:], tok)
		if i < 0 {
			return false
		}
		i += start
		before := i == 0 || !isAlnum(s[i-1])
		end := i + len(tok)
		after := end == len(s) || !isAlnum(s[end])
		if before && after {
			return true
		}
		start = i + 1
	}
	return false
}

func isAlnum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
