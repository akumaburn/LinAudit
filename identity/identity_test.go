package identity

import (
	"strings"
	"testing"
)

// TestSoleLoginUserFrom locks the /etc/passwd heuristic: exactly one regular
// login account (uid 1000-60000, real shell) yields that name; zero or several
// yield "" so callers fall back rather than guess wrong.
func TestSoleLoginUserFrom(t *testing.T) {
	cases := []struct {
		name, passwd, want string
	}{
		{
			"single human among system accounts",
			"root:x:0:0:root:/root:/bin/bash\n" +
				"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
				"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n" +
				"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
			"alice",
		},
		{
			"two humans -> ambiguous",
			"alice:x:1000:1000::/home/alice:/bin/bash\n" +
				"bob:x:1001:1001::/home/bob:/bin/zsh\n",
			"",
		},
		{
			"no human accounts",
			"root:x:0:0:root:/root:/bin/bash\n" +
				"svc:x:200:200::/var/lib/svc:/usr/sbin/nologin\n",
			"",
		},
		{
			"nologin/false shells skipped, one real remains",
			"alice:x:1000:1000::/home/alice:/usr/bin/zsh\n" +
				"sys:x:1001:1001::/srv/sys:/sbin/nologin\n" +
				"build:x:1002:1002::/srv/build:/bin/false\n",
			"alice",
		},
		{
			"uid below 1000 ignored (system range)",
			"messagebus:x:101:101::/nonexistent:/usr/sbin/nologin\n" +
				"chrony:x:990:990::/var/lib/chrony:/usr/sbin/nologin\n",
			"",
		},
	}
	for _, c := range cases {
		if got := soleLoginUserFrom(strings.NewReader(c.passwd)); got != c.want {
			t.Errorf("%s: soleLoginUserFrom = %q, want %q", c.name, got, c.want)
		}
	}
}
