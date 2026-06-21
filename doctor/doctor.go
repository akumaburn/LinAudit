// Package doctor implements `linaudit doctor`: a read-only preflight that reports,
// on ANY Linux distro, exactly which LinAudit functionality will work here and
// what is missing. It checks the kernel/arch, init system, required and optional
// external tools, the TPM, the device and kernel interfaces each plane needs, the
// resolved monitored user, and the live service/mount state.
package doctor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"linaudit/identity"
)

// netlinkSockDiag is NETLINK_SOCK_DIAG (the protocol the network plane uses).
const netlinkSockDiag = 4

type level int

const (
	ok level = iota
	warn
	miss
)

type result struct {
	lvl    level
	label  string
	detail string
}

// Run prints the diagnostic report and returns an error if a core requirement is
// missing (so it is scriptable), nil otherwise.
func Run() error {
	var rs []result
	add := func(l level, label, detail string) { rs = append(rs, result{l, label, detail}) }

	// --- platform ---
	add(ok, "platform", fmt.Sprintf("%s/%s, kernel %s, %s", runtime.GOOS, runtime.GOARCH, kernelRelease(), distro()))
	if runtime.GOOS != "linux" {
		add(miss, "os", "LinAudit requires Linux")
	}

	// --- init system ---
	if dirExists("/run/systemd/system") {
		add(ok, "systemd", "booted with systemd"+systemdVersion())
	} else {
		add(warn, "systemd", "not detected -- service management (store/input/web units, enable/disable) is unavailable; `linaudit web|input` can still be run manually")
	}

	// --- required external tools (encrypted store) ---
	for _, t := range []string{"cryptsetup", "systemd-creds", "mkfs.ext4", "mount", "umount"} {
		if p, err := exec.LookPath(t); err == nil {
			add(ok, "tool:"+t, p)
		} else {
			add(miss, "tool:"+t, "not found in PATH -- the encrypted log store cannot be created/mounted")
		}
	}
	// --- optional external tools ---
	for _, t := range []string{"systemctl", "journalctl", "auditctl", "nvidia-smi", "xdg-open"} {
		if p, err := exec.LookPath(t); err == nil {
			add(ok, "tool:"+t+" (optional)", p)
		} else {
			add(warn, "tool:"+t+" (optional)", optionalNote(t))
		}
	}

	// --- shell plane (prompt/command capture hooks) ---
	var shells []string
	for _, s := range []string{"bash", "zsh", "fish"} {
		if _, err := exec.LookPath(s); err == nil {
			shells = append(shells, s)
		}
	}
	if len(shells) > 0 {
		add(ok, "shell plane", fmt.Sprintf("hookable shells: %s -- executed commands captured for all; zsh also records unexecuted prompt text", strings.Join(shells, ", ")))
	} else {
		add(warn, "shell plane", "no supported shell (bash/zsh/fish) found in PATH -- the prompt/command plane is unavailable")
	}

	// --- TPM2 (key sealing) ---
	if dirExists("/dev/tpmrm0") || dirExists("/dev/tpm0") {
		add(ok, "tpm2", "/dev/tpmrm0 present -- store key sealed to the TPM")
	} else {
		add(warn, "tpm2", "no TPM2 device -- the store key seals to the HOST only (no hardware binding)")
	}

	// --- kernel interfaces ---
	if netlinkOK() {
		add(ok, "netlink sock_diag", "NETLINK_SOCK_DIAG socket created -- network plane OK")
	} else {
		add(miss, "netlink sock_diag", "cannot open NETLINK_SOCK_DIAG -- network bandwidth/connections unavailable (need CONFIG_INET_DIAG)")
	}
	if canStat("/proc/self/stat") && canStat("/proc/stat") {
		add(ok, "/proc", "readable -- process monitor OK")
	} else {
		add(miss, "/proc", "not readable -- process monitor unavailable")
	}

	// --- offline network-enrichment databases (optional; degrade gracefully) ---
	const geoDir = "/usr/local/share/linaudit/geoip"
	if fileExists(geoDir+"/ipv4.csv") && fileExists(geoDir+"/ipv6.csv") {
		add(ok, "geoip country db", geoDir+" -- connections resolve to country + world map")
	} else {
		add(warn, "geoip country db", "absent -- run `sudo sh data/fetch-geoip.sh`; the country column and map degrade gracefully")
	}
	if fileExists(geoDir+"/asn-ipv4.csv") && fileExists(geoDir+"/asn-ipv6.csv") {
		add(ok, "asn/org db", geoDir+" -- peers classified by owning network (corp/cloud/cdn/gov/telecom)")
	} else {
		add(warn, "asn/org db", "absent -- run `sudo sh data/fetch-geoip.sh`; the owner column shows 'unknown' for every peer")
	}
	rs = append(rs, inputDevicesLevel())
	if fileExists("/dev/uinput") {
		add(ok, "/dev/uinput", "present -- software-injection (uinput) auditing possible")
	} else {
		add(warn, "/dev/uinput", "absent -- load the `uinput` module to detect software injectors")
	}

	// --- identity ---
	if u := identity.User(); u != "" {
		add(ok, "monitored user", fmt.Sprintf("%s (home %s)", u, dash(identity.Home())))
	} else {
		add(warn, "monitored user", "unresolved -- set LINAUDIT_USER (the shell plane needs it); other planes are unaffected")
	}

	// --- live state ---
	if isMounted("/var/log/linaudit") {
		add(ok, "log store", "/var/log/linaudit is mounted")
	} else {
		add(warn, "log store", "/var/log/linaudit not mounted -- run `sudo linaudit store init` (once) then `store up`")
	}
	if dirExists("/run/systemd/system") {
		for _, svc := range []string{"linaudit-store.service", "linaudit-input.service", "linaudit-web.service", "auditd.service"} {
			if serviceActive(svc) {
				add(ok, "service:"+svc, "active")
			} else {
				add(warn, "service:"+svc, "not active")
			}
		}
	}
	if r, show := auditFloodLevel(); show {
		rs = append(rs, r)
	}

	print(rs)
	for _, r := range rs {
		if r.lvl == miss {
			return fmt.Errorf("one or more core requirements are missing (see [MISS] above)")
		}
	}
	return nil
}

// --- printing ---

func print(rs []result) {
	tty := isTTY()
	green, yellow, red, dim, reset := "", "", "", "", ""
	if tty {
		green, yellow, red, dim, reset = "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[2m", "\x1b[0m"
	}
	tag := map[level]string{
		ok:   green + "[ OK ]" + reset,
		warn: yellow + "[WARN]" + reset,
		miss: red + "[MISS]" + reset,
	}
	fmt.Println("LinAudit doctor -- environment readiness")
	fmt.Println(strings.Repeat("-", 60))
	var nOK, nWarn, nMiss int
	for _, r := range rs {
		switch r.lvl {
		case ok:
			nOK++
		case warn:
			nWarn++
		case miss:
			nMiss++
		}
		fmt.Printf("  %s %-26s %s%s%s\n", tag[r.lvl], r.label, dim, r.detail, reset)
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  %d ok, %d warnings, %d missing\n", nOK, nWarn, nMiss)
	if nMiss == 0 {
		fmt.Println("  core monitoring is supported on this host.")
	} else {
		fmt.Println("  some core functionality is unavailable; see [MISS] lines above.")
	}
}

// --- checks ---

func netlinkOK() bool {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkSockDiag)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// inputDevicesLevel reports on /dev/input access (root is needed to read events).
func inputDevicesLevel() result {
	ents, err := os.ReadDir("/dev/input")
	if err != nil {
		return result{miss, "/dev/input", "unreadable -- input-source attribution unavailable"}
	}
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "event") {
			n++
		}
	}
	if n == 0 {
		return result{warn, "/dev/input", "no event devices found"}
	}
	if os.Geteuid() != 0 {
		return result{ok, "/dev/input", fmt.Sprintf("%d event device(s); the input logger runs as root", n)}
	}
	return result{ok, "/dev/input", fmt.Sprintf("%d event device(s) readable", n)}
}

func serviceActive(svc string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", svc).Run() == nil
}

// auditFloodLevel reports on the kernel audit "subj_ctx" log-flood condition.
//
// On some kernels (observed on 7.0.x Manjaro) audit_log_subj_ctx() cannot render
// the optional subj= label for AppArmor-unconfined tasks; because the audit
// failure mode is PRINTK the kernel floods the ring buffer with
// "audit: error in audit_log_subj_ctx", and every auditctl AUDIT_SET is rejected
// so it cannot be silenced with `auditctl -f 0`. LinAudit ships
// system/99-linaudit-audit-quiet.conf to throttle it at the printk layer.
//
// This is best-effort and avoids false positives: it returns a line only when the
// mitigation is active (OK) or when the affected condition is positively
// confirmed (WARN). Confirmation needs root (to read the audit failure mode); when
// it is unavailable, or the host is not affected, no line is emitted.
func auditFloodLevel() (result, bool) {
	if _, err := exec.LookPath("auditctl"); err != nil {
		return result{}, false
	}
	if !serviceActive("auditd.service") {
		return result{}, false
	}
	if mitigationActive() {
		return result{ok, "audit log flood", "printk-ratelimit mitigation active (99-linaudit-audit-quiet.conf) -- AppArmor subj_ctx errors throttled"}, true
	}
	mode, okRead := auditFailureMode()
	if !okRead {
		return result{}, false // needs root to read; assessed when run as root
	}
	if mode != auditFailPrintk {
		return result{}, false // silent/panic failure mode does not spam the kernel log
	}
	if !apparmorEnabled() {
		return result{}, false // the flood is an AppArmor subject-context failure
	}
	// No-op probe: re-assert the CURRENT failure mode. This succeeds on healthy
	// kernels (no state change) and errors on the affected kernels, which reject
	// every audit reconfiguration -- the reliable tell. A healthy PRINTK kernel
	// resolves the AppArmor context fine and does not flood, so we do not warn.
	if exec.Command("auditctl", "-f", strconv.Itoa(mode)).Run() == nil {
		return result{}, false
	}
	return result{warn, "audit log flood", "kernel floods dmesg with 'error in audit_log_subj_ctx' (AppArmor subj ctx) and rejects `auditctl -f 0` -- run `sudo install -m644 system/99-linaudit-audit-quiet.conf /etc/sysctl.d/ && sudo sysctl --system`, or boot a kernel without the regression"}, true
}

// auditFailPrintk is AUDIT_FAIL_PRINTK: the audit failure mode that logs delivery
// failures (incl. subj_ctx errors) to the kernel ring buffer.
const auditFailPrintk = 1

// mitigationActive reports whether the printk-ratelimit drop-in is installed and
// in effect (the kernel default burst is 10; the drop-in lowers it).
func mitigationActive() bool {
	if !fileExists("/etc/sysctl.d/99-linaudit-audit-quiet.conf") {
		return false
	}
	b, err := os.ReadFile("/proc/sys/kernel/printk_ratelimit_burst")
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && n < 10
}

// auditFailureMode returns the kernel audit failure mode (0 silent, 1 printk,
// 2 panic) parsed from `auditctl -s`. The bool is false when it cannot be read
// (auditctl absent, or not running as root).
func auditFailureMode() (int, bool) {
	out, err := exec.Command("auditctl", "-s").Output()
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if v, found := strings.CutPrefix(sc.Text(), "failure "); found {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// apparmorEnabled reports whether AppArmor is the active LSM (its subject-context
// resolution is what fails in the audit_log_subj_ctx flood).
func apparmorEnabled() bool {
	b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	return err == nil && strings.TrimSpace(string(b)) == "Y"
}

func isMounted(path string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}
	return false
}

func kernelRelease() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "?"
}

func distro() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown distro"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, found := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); found {
			return strings.Trim(v, `"`)
		}
	}
	return "unknown distro"
}

func systemdVersion() string {
	out, err := exec.Command("systemctl", "--version").Output()
	if err != nil {
		return ""
	}
	if line, _, ok := strings.Cut(string(out), "\n"); ok {
		return " (" + strings.TrimSpace(line) + ")"
	}
	return ""
}

func optionalNote(tool string) string {
	switch tool {
	case "auditctl":
		return "auditd absent -- exec/uinput/USB audit plane off (install: apt install auditd / dnf install audit / pacman -S audit)"
	case "nvidia-smi":
		return "absent -- per-process GPU VRAM will be omitted (non-NVIDIA hosts: expected)"
	case "xdg-open":
		return "absent -- `linaudit open` falls back to BROWSER / brave / firefox"
	default:
		return "absent (optional)"
	}
}

// --- small fs helpers ---

func dirExists(p string) bool  { _, err := os.Stat(p); return err == nil }
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func canStat(p string) bool    { _, err := os.Stat(p); return err == nil }

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func isTTY() bool {
	fi, _ := os.Stdout.Stat()
	return fi != nil && fi.Mode()&os.ModeCharDevice != 0
}
