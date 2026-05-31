// Package identity resolves the human (non-root) account that LinAudit monitors,
// plus that account's home directory and uid/gid. The store and web services run
// as root, so the user cannot be taken from the running process; it is detected
// from the environment and the system in order of decreasing authority:
//
//  1. $LINAUDIT_USER            explicit override (also set by the installer)
//  2. $SUDO_USER (!= root)      the human who ran a `sudo linaudit ...` command
//  3. the current user          only when not running as root (e.g. the CLI)
//  4. owner of /var/log/linaudit/shell, if it exists and is not root-owned
//  5. the sole regular login account in /etc/passwd (uid 1000-60000, real shell)
//
// If nothing resolves, User()/Home() return "" and IDs() returns ok=false; every
// caller is expected to degrade gracefully rather than fail. This replaces the
// former hardcoded "aeslampanah" default, which broke every other machine.
package identity

import (
	"bufio"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

const shellLogDir = "/var/log/linaudit/shell"

// nonLoginShells are login shells that mark a system/service account, never a human.
var nonLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "": true,
}

// User returns the resolved monitored account name, or "" if undetermined.
func User() string {
	if u := lookupValid(os.Getenv("LINAUDIT_USER")); u != nil {
		return u.Username
	}
	if s := os.Getenv("SUDO_USER"); s != "" && s != "root" {
		if u := lookupValid(s); u != nil {
			return u.Username
		}
	}
	if os.Geteuid() != 0 {
		if u, err := user.Current(); err == nil && u.Username != "" && u.Username != "root" {
			return u.Username
		}
	}
	if name := ownerOfShellDir(); name != "" {
		return name
	}
	return soleLoginUser()
}

// Home returns the monitored user's home directory, or "" if undetermined.
func Home() string {
	if u := lookupValid(User()); u != nil {
		return u.HomeDir
	}
	return ""
}

// IDs returns the monitored user's uid/gid; ok is false when undetermined or when
// the resolved account is root (uid 0 is never a valid monitored user).
func IDs() (uid, gid int, ok bool) {
	u := lookupValid(User())
	if u == nil {
		return 0, 0, false
	}
	ui, err1 := strconv.Atoi(u.Uid)
	gi, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || ui == 0 {
		return 0, 0, false
	}
	return ui, gi, true
}

func lookupValid(name string) *user.User {
	if name == "" {
		return nil
	}
	if u, err := user.Lookup(name); err == nil {
		return u
	}
	return nil
}

// ownerOfShellDir returns the name of the account owning /var/log/linaudit/shell
// (set up by the store for the monitored user), or "" if missing or root-owned.
func ownerOfShellDir() string {
	fi, err := os.Stat(shellLogDir)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return ""
	}
	if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil {
		return u.Username
	}
	return ""
}

// soleLoginUser returns the single regular login account from /etc/passwd (uid in
// [1000, 60000] with a real login shell). If there is not exactly one, returns "".
func soleLoginUser() string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()
	return soleLoginUserFrom(f)
}

// soleLoginUserFrom is the testable core of soleLoginUser.
func soleLoginUserFrom(r io.Reader) string {
	var found string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < 1000 || uid > 60000 {
			continue
		}
		if nonLoginShells[fields[6]] {
			continue
		}
		if found != "" {
			return "" // more than one regular account: ambiguous
		}
		found = fields[0]
	}
	return found
}
