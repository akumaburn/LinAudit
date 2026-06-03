// Package cli implements the LinAudit control-panel commands that previously
// lived in the cli/linaudit bash script. It exposes the verbs wired up by
// cmd/linaudit/main.go: Status, Enable, Disable, Logs, Report, Live, Open and
// Menu. The package shells out to systemd/journalctl/sudo for the operations
// that require privilege or live tailing, but reads the user-owned buffer and
// command logs directly. It depends only on the Go standard library.
package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"linaudit/identity"
)

// Hardcoded paths and identity for this deployment. The user (and therefore the
// home directory) can be overridden via LINAUDIT_USER; everything else is
// derived from the resolved home directory or is a fixed system path.
const (
	keyLog = "/var/log/linaudit/input/keys.log"

	inputService = "linaudit-input.service"
	auditService = "auditd.service"

	dashboardURL = "http://127.0.0.1:8799/"
)

// ANSI colour codes, only emitted when stdout is a TTY (see colors()).
type palette struct {
	R, G, Y, C, M, Dim, Bold, N string
}

// colors returns the active palette: real ANSI escapes on a TTY, empty strings
// otherwise so piped/redirected output stays clean.
func colors() palette {
	if isTTY() {
		return palette{
			R:    "\x1b[31m",
			G:    "\x1b[32m",
			Y:    "\x1b[33m",
			C:    "\x1b[36m",
			M:    "\x1b[35m",
			Dim:  "\x1b[2m",
			Bold: "\x1b[1m",
			N:    "\x1b[0m",
		}
	}
	return palette{}
}

// isTTY reports whether stdout is a character device (an interactive terminal).
func isTTY() bool {
	fi, _ := os.Stdout.Stat()
	return fi != nil && fi.Mode()&os.ModeCharDevice != 0
}

// userName resolves the monitored account via the shared detector (LINAUDIT_USER
// > SUDO_USER > current user > store-dir owner > sole login user), falling back to
// the current process user so an interactive operator is always covered.
func userName() string {
	if u := identity.User(); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// home resolves the monitored user's home directory, falling back to the current
// user's home so an interactive operator always sees their own logs.
func home() string {
	if h := identity.Home(); h != "" {
		return h
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	h, _ := os.UserHomeDir()
	return h
}

// paths bundles the per-user log/flag locations derived from the home directory,
// plus the rc / drop-in locations for each supported shell's hook.
type paths struct {
	zdir     string
	buflog   string
	cmdlog   string
	disflag  string
	zshrc    string
	bashrc   string
	fishconf string
}

// resolvePaths computes the user-relative paths for this invocation.
func resolvePaths() paths {
	h := home()
	zdir := filepath.Join(h, ".local", "share", "linaudit")
	return paths{
		zdir:     zdir,
		buflog:   filepath.Join(zdir, "buffer.log"),
		cmdlog:   filepath.Join(zdir, "commands.log"),
		disflag:  filepath.Join(zdir, "disabled"),
		zshrc:    filepath.Join(h, ".zshrc"),
		bashrc:   filepath.Join(h, ".bashrc"),
		fishconf: filepath.Join(h, ".config", "fish", "conf.d", "linaudit.fish"),
	}
}

// -------------------------------------------------------------------------
// layer state
// -------------------------------------------------------------------------

// shellOn reports whether the shell-capture plane is active: at least one
// supported shell (zsh/bash/fish) wires the LinAudit hook AND the shared disabled
// flag is absent (one flag gates every shell).
func shellOn(p paths) bool {
	return shellHookWired(p) && !fileExists(p.disflag)
}

// shellHookWired reports whether any supported shell sources/auto-loads the hook:
// zsh (.zshrc), bash (.bashrc), or fish (the auto-loaded conf.d drop-in).
func shellHookWired(p paths) bool {
	return fileContains(p.zshrc, "linaudit.zsh") ||
		fileContains(p.bashrc, "linaudit.bash") ||
		fileExists(p.fishconf)
}

// svcActive reports whether a systemd unit is active (is-active exit 0).
func svcActive(name string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

// fileExists reports whether path exists (any stat success).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fileContains reports whether the file at path contains needle as a substring.
// Missing/unreadable files report false (matching grep -q's silent failure).
func fileContains(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte(needle))
}

// dot renders a filled green dot for on, an empty red dot for off.
func dot(pal palette, on bool) string {
	if on {
		return pal.G + "●" + pal.N
	}
	return pal.R + "○" + pal.N
}

// -------------------------------------------------------------------------
// Status
// -------------------------------------------------------------------------

// Status prints the three monitoring-layer states (shell, input, audit) and the
// size/line count of the three log files. keys.log usually requires root, so a
// permission failure degrades to "-"/"?" rather than aborting.
func Status() error {
	p := resolvePaths()
	pal := colors()
	out := os.Stdout

	fmt.Fprintf(out, "%s  LinAudit  %s%smonitoring control panel%s\n", pal.Bold, pal.N, pal.Dim, pal.N)
	fmt.Fprintln(out, "  ----------------------------------------------------------")

	fmt.Fprintf(out, "   %s  %-26s %s\n",
		dot(pal, shellOn(p)), "shell prompt + command log",
		pal.Dim+"exec'd cmds (bash/zsh/fish) + prompt text (zsh)"+pal.N)
	fmt.Fprintf(out, "   %s  %-26s %s\n",
		dot(pal, svcActive(inputService)), "input-device attribution",
		pal.Dim+"which device emitted each keystroke"+pal.N)
	fmt.Fprintf(out, "   %s  %-26s %s\n",
		dot(pal, svcActive(auditService)), "auditd exec/uinput/usb",
		pal.Dim+"executions, injection & BadUSB"+pal.N)

	fmt.Fprintln(out, "  ----------------------------------------------------------")

	printLogLine(out, pal, "buffer.log", p.buflog, false)
	printLogLine(out, pal, "commands.log", p.cmdlog, false)
	printLogLine(out, pal, "keys.log", keyLog, true)
	fmt.Fprintln(out)
	return nil
}

// printLogLine prints one "<name>  <size>  <N> lines" status row. When privileged
// is true the file is read directly first and, on a permission error, the size
// and line count fall back to "-"/"?" (keys.log is root-owned).
func printLogLine(w io.Writer, pal palette, name, path string, privileged bool) {
	size, lines, ok := logStat(path)
	sizeStr := "-"
	linesStr := "0"
	if ok {
		sizeStr = humanSize(size)
		linesStr = strconv.Itoa(lines)
	} else if privileged {
		// Unreadable root-owned log: try sudo, then degrade gracefully.
		if s, l, sok := sudoLogStat(path); sok {
			sizeStr = humanSize(s)
			linesStr = strconv.Itoa(l)
		} else {
			sizeStr = "-"
			linesStr = "?"
		}
	}
	fmt.Fprintf(w, "   %s%-16s%s %6s  %s lines\n", pal.C, name, pal.N, sizeStr, linesStr)
}

// logStat returns the byte size and newline count of a directly readable file.
// ok is false on any read error (e.g. permission denied or missing file).
func logStat(path string) (size int64, lines int, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, false
	}
	n, err := countNewlines(f)
	if err != nil {
		return 0, 0, false
	}
	return fi.Size(), n, true
}

// sudoLogStat reads a root-owned log's size and line count via sudo, used only as
// a best-effort fallback for keys.log in Status.
func sudoLogStat(path string) (size int64, lines int, ok bool) {
	out, err := exec.Command("sudo", "wc", "-c", "-l", path).Output()
	if err != nil {
		return 0, 0, false
	}
	// `wc -c -l` prints: "<lines> <bytes> <path>".
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return 0, 0, false
	}
	l, err1 := strconv.Atoi(fields[0])
	b, err2 := strconv.ParseInt(fields[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return b, l, true
}

// countNewlines counts '\n' bytes in r using a fixed buffer (no full load).
func countNewlines(r io.Reader) (int, error) {
	buf := make([]byte, 64*1024)
	count := 0
	for {
		n, err := r.Read(buf)
		count += bytes.Count(buf[:n], []byte{'\n'})
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
	}
}

// humanSize renders a byte count like `du -h` (K/M/G with one decimal place when
// fractional, matching the previous bash output's intent).
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	suffixes := []string{"K", "M", "G", "T", "P"}
	suffix := suffixes[exp]
	if val >= 10 || val == float64(int64(val)) {
		return strconv.FormatInt(int64(val+0.5), 10) + suffix
	}
	return strconv.FormatFloat(val, 'f', 1, 64) + suffix
}

// -------------------------------------------------------------------------
// Enable / Disable
// -------------------------------------------------------------------------

// Enable activates the given layer (shell, input, audit or all) then prints
// Status. The shell plane covers every supported shell; "zsh"/"bash"/"fish" are
// accepted as aliases for it (capture is gated by one shared flag).
func Enable(layer string) error {
	p := resolvePaths()
	switch layer {
	case "shell", "zsh", "bash", "fish":
		return finishToggle(enableShell(p))
	case "input":
		return finishToggle(enableService(inputService, false))
	case "audit":
		return finishToggle(enableService(auditService, true))
	case "all":
		err := enableShell(p)
		if e := enableService(inputService, false); err == nil {
			err = e
		}
		if e := enableService(auditService, true); err == nil {
			err = e
		}
		return finishToggle(err)
	default:
		fmt.Fprintln(os.Stdout, "enable shell|input|audit|all")
		return Status()
	}
}

// Disable deactivates the given layer (shell, input, audit or all) then prints
// Status. The shell plane covers every supported shell; "zsh"/"bash"/"fish" are
// accepted as aliases for it (capture is gated by one shared flag).
func Disable(layer string) error {
	p := resolvePaths()
	switch layer {
	case "shell", "zsh", "bash", "fish":
		return finishToggle(disableShell(p))
	case "input":
		return finishToggle(disableService(inputService))
	case "audit":
		return finishToggle(disableService(auditService))
	case "all":
		err := disableShell(p)
		if e := disableService(inputService); err == nil {
			err = e
		}
		if e := disableService(auditService); err == nil {
			err = e
		}
		return finishToggle(err)
	default:
		fmt.Fprintln(os.Stdout, "disable shell|input|audit|all")
		return Status()
	}
}

// finishToggle reports any toggle error to stderr (without aborting the command)
// and always prints the refreshed Status, mirroring the bash script which prints
// status unconditionally after enable/disable.
func finishToggle(err error) error {
	if err != nil {
		fmt.Fprintf(os.Stderr, "linaudit: %v\n", err)
	}
	return Status()
}

// enableShell wires the LinAudit hook into each installed supported shell's rc
// (zsh -> ~/.zshrc, bash -> ~/.bashrc) with a guarded source line, then clears
// the shared disabled flag. fish auto-loads its hook from ~/.config/fish/conf.d,
// so it needs no rc edit (the drop-in is placed by the installer). Each source
// line is guarded, so it is harmless even if a given hook file is not present.
func enableShell(p paths) error {
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if commandExists("zsh") {
		note(wireRc(p.zshrc,
			"[[ -f ~/.config/zsh/linaudit.zsh ]] && source ~/.config/zsh/linaudit.zsh",
			"linaudit.zsh"))
	}
	if commandExists("bash") {
		note(wireRc(p.bashrc,
			"[ -f ~/.config/bash/linaudit.bash ] && . ~/.config/bash/linaudit.bash",
			"linaudit.bash"))
	}
	// fish needs no rc edit: ~/.config/fish/conf.d/linaudit.fish auto-loads.
	if err := os.Remove(p.disflag); err != nil && !os.IsNotExist(err) {
		note(fmt.Errorf("remove disabled flag: %w", err))
	}
	return firstErr
}

// wireRc appends a "# LinAudit" + source line to rc when marker is not already
// present, creating rc if needed.
func wireRc(rc, sourceLine, marker string) error {
	if fileContains(rc, marker) {
		return nil
	}
	block := "\n# LinAudit\n" + sourceLine + "\n"
	f, err := os.OpenFile(rc, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("append %s: %w", rc, err)
	}
	if _, err := f.WriteString(block); err != nil {
		f.Close()
		return fmt.Errorf("append %s: %w", rc, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("append %s: %w", rc, err)
	}
	return nil
}

// commandExists reports whether name resolves on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// disableShell creates/truncates the shared disabled flag file. Every shell hook
// (bash/zsh/fish) checks this flag before logging, so one flag disables all of
// them at once.
func disableShell(p paths) error {
	if err := os.MkdirAll(p.zdir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	f, err := os.OpenFile(p.disflag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create disabled flag: %w", err)
	}
	return f.Close()
}

// enableService runs `sudo systemctl enable --now <svc>`, and for the audit
// service additionally `sudo auditctl -e 1`. Output is inherited so sudo can
// prompt on the controlling terminal.
func enableService(svc string, audit bool) error {
	if audit && !auditdInstalled() {
		fmt.Fprintln(os.Stderr, "auditd is not installed; the exec / uinput / USB audit plane is unavailable.")
		fmt.Fprintln(os.Stderr, "  install it:  Debian/Ubuntu/Mint/Pop -> sudo apt install auditd  |  Fedora/RHEL -> sudo dnf install audit  |  Arch/Manjaro -> sudo pacman -S audit  |  openSUSE -> sudo zypper install audit")
		return nil
	}
	if err := runInteractive("sudo", "systemctl", "enable", "--now", svc); err != nil {
		return err
	}
	if audit {
		// auditctl output is discarded in the bash original (>/dev/null).
		cmd := exec.Command("sudo", "auditctl", "-e", "1")
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("auditctl -e 1: %w", err)
		}
	}
	return nil
}

// disableService runs `sudo systemctl disable --now <svc>`.
func disableService(svc string) error {
	return runInteractive("sudo", "systemctl", "disable", "--now", svc)
}

// auditdInstalled reports whether the auditd unit exists on this host. The audit
// package is NOT installed by default on most distros, so enabling it blindly
// produces a confusing systemctl error; callers warn instead.
func auditdInstalled() bool {
	out, _ := exec.Command("systemctl", "list-unit-files", auditService, "--no-legend").Output()
	return strings.Contains(string(out), "auditd")
}

// runInteractive runs a command with the parent's stdio attached so sudo can
// prompt for a password and the user sees systemd output.
func runInteractive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Logs
// -------------------------------------------------------------------------

// Logs displays a log "view": buffer, exec, keys, devices or usb. Content is
// paged through $PAGER (default "less -R") when stdout is a TTY, otherwise it is
// written straight to stdout.
func Logs(which string) error {
	p := resolvePaths()
	switch which {
	case "buffer":
		return pageFile(p.buflog, false)
	case "exec":
		return pageFile(p.cmdlog, false)
	case "keys":
		return pageFile(keyLog, true)
	case "devices":
		return pageDevices()
	case "usb":
		return pageUSB()
	default:
		fmt.Fprintf(os.Stdout, "unknown log '%s' (buffer|exec|keys|devices|usb)\n", which)
		return nil
	}
}

// pageFile streams a log file to the pager (or stdout). Root-owned files are read
// via `sudo cat` when a direct read is denied.
func pageFile(path string, privileged bool) error {
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		return page(f)
	}
	if privileged && os.IsPermission(err) {
		return pageSudoCat(path)
	}
	if os.IsNotExist(err) {
		return page(strings.NewReader(fmt.Sprintf("(unavailable: %v)\n", err)))
	}
	if privileged {
		return pageSudoCat(path)
	}
	return page(strings.NewReader(fmt.Sprintf("(unavailable: %v)\n", err)))
}

// pageSudoCat pipes `sudo cat <path>` into the pager (or stdout).
func pageSudoCat(path string) error {
	cmd := exec.Command("sudo", "cat", path)
	return pageCmd(cmd)
}

// pageDevices filters the keystroke log for device lifecycle markers and pages
// the result, reading via sudo since keys.log is root-owned.
func pageDevices() error {
	// `sudo grep -E 'DEVICE_ADDED|DEVICE_REMOVED|AUDIT_START' KEYLOG`.
	cmd := exec.Command("sudo", "grep", "-E", "DEVICE_ADDED|DEVICE_REMOVED|AUDIT_START", keyLog)
	return pageCmd(cmd)
}

// pageUSB pages the recent linaudit-usb / linaudit-input journal entries.
func pageUSB() error {
	cmd := exec.Command("journalctl", "-t", "linaudit-usb", "-t", "linaudit-input",
		"-n", "100", "--no-pager")
	return pageCmd(cmd)
}

// pageCmd runs cmd, feeding its combined stdout into the pager (or stdout). grep
// returns exit status 1 when there are no matches; that is not treated as a hard
// error.
func pageCmd(cmd *exec.Cmd) error {
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// Non-zero (e.g. grep no-match): still page whatever was produced.
			_ = ee
		} else {
			return page(strings.NewReader(fmt.Sprintf("(unavailable: %v)\n", err)))
		}
	}
	return page(bytes.NewReader(out))
}

// page sends r to $PAGER (default "less -R") when stdout is a TTY, otherwise
// copies it straight to stdout. A pager launch failure falls back to stdout.
func page(r io.Reader) error {
	if !isTTY() {
		_, err := io.Copy(os.Stdout, r)
		return err
	}
	name, args := pagerCommand()
	cmd := exec.Command(name, args...)
	cmd.Stdin = r
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Pager unavailable: fall back to plain stdout.
		_, copyErr := io.Copy(os.Stdout, r)
		return copyErr
	}
	return nil
}

// pagerCommand returns the pager program and its arguments. It honours $PAGER
// (split on spaces) and defaults to `less -R`.
func pagerCommand() (string, []string) {
	if v := strings.TrimSpace(os.Getenv("PAGER")); v != "" {
		fields := strings.Fields(v)
		return fields[0], fields[1:]
	}
	return "less", []string{"-R"}
}

// -------------------------------------------------------------------------
// Report
// -------------------------------------------------------------------------

// reportItem is one correlated timeline entry.
type reportItem struct {
	ts     float64
	tag    string
	detail string
}

// Report correlates the last N prompt (buffer) entries with exec, keystroke and
// device events on a shared timeline and prints them. The correlation logic
// mirrors the web report(): tab-split fields, BUFFER -> BUF, EXEC -> EXEC, KEY
// and DEVICE_* from the keystroke log, all filtered to ts >= the first buffer
// entry's timestamp and sorted ascending.
func Report(arg string) error {
	return reportTo(os.Stdout, arg)
}

// reportTo writes the correlated timeline to out. Report sends it to stdout; the
// interactive menu captures the output and pages it (mirroring the bash
// `report 25 | less -R`).
func reportTo(out io.Writer, arg string) error {
	n := 15
	if v, err := strconv.Atoi(strings.TrimSpace(arg)); err == nil {
		n = v
	}
	p := resolvePaths()
	pal := colors()

	items := buildReport(p, n)
	if len(items) == 0 {
		fmt.Fprintln(out, "no prompt entries logged yet.")
		return nil
	}

	fmt.Fprintf(out, "%s  correlated timeline (last %d prompt entries)%s\n", pal.Bold, n, pal.N)
	fmt.Fprintf(out, "  %stime          plane  detail%s\n", pal.Dim, pal.N)
	for _, it := range items {
		col := pal.N
		switch it.tag {
		case "BUF":
			col = pal.M
		case "EXEC":
			col = pal.Y
		case "KEY":
			col = pal.Dim
		case "DEV":
			col = pal.R
		}
		fmt.Fprintf(out, "  %s  %s%-5s%s  %s\n", formatTS(it.ts), col, it.tag, pal.N, it.detail)
	}
	return nil
}

// buildReport reproduces web/server.py report(n): it reads the tail of the
// buffer, command and key logs, applies the same field/timestamp filters and
// returns the merged, ascending-sorted timeline. keys.log is read via sudo when
// a direct read is denied (best effort).
func buildReport(p paths, n int) []reportItem {
	var bufs []reportItem
	for _, line := range tailLines(p.buflog, 6000, false) {
		f := strings.Split(line, "\t")
		if len(f) >= 6 && f[4] == "BUFFER" {
			if ts, err := strconv.ParseFloat(f[1], 64); err == nil {
				bufs = append(bufs, reportItem{ts: ts, tag: "BUF", detail: f[5]})
			}
		}
	}
	if len(bufs) > n {
		bufs = bufs[len(bufs)-n:]
	}
	if len(bufs) == 0 {
		return nil
	}
	t0 := bufs[0].ts

	merged := make([]reportItem, len(bufs))
	copy(merged, bufs)

	for _, line := range tailLines(p.cmdlog, 6000, false) {
		f := strings.Split(line, "\t")
		if len(f) >= 6 && f[4] == "EXEC" {
			ts, err := strconv.ParseFloat(f[1], 64)
			if err != nil {
				continue
			}
			if ts >= t0 {
				merged = append(merged, reportItem{ts: ts, tag: "EXEC", detail: f[5]})
			}
		}
	}

	for _, line := range tailLines(keyLog, 12000, true) {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		ts, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		if ts < t0 {
			continue
		}
		switch {
		case f[1] == "KEY" && len(f) >= 6:
			merged = append(merged, reportItem{ts: ts, tag: "KEY",
				detail: f[3] + " " + f[4] + " val=" + f[5]})
		case f[1] == "DEVICE_ADDED" || f[1] == "DEVICE_REMOVED":
			dev := ""
			if len(f) >= 4 {
				dev = f[3]
			}
			merged = append(merged, reportItem{ts: ts, tag: "DEV", detail: f[1] + " " + dev})
		}
	}

	sort.SliceStable(merged, func(i, j int) bool { return merged[i].ts < merged[j].ts })
	return merged
}

// formatTS renders a float epoch timestamp as local "HH:MM:SS.mmm".
func formatTS(ts float64) string {
	sec := int64(ts)
	frac := ts - float64(sec)
	ms := int(frac * 1000)
	if ms < 0 {
		ms = 0
	}
	if ms > 999 {
		ms = 999
	}
	t := time.Unix(sec, 0)
	return fmt.Sprintf("%s.%03d", t.Format("15:04:05"), ms)
}

// -------------------------------------------------------------------------
// tail helpers (read the last ~512KiB and return up to n trailing lines)
// -------------------------------------------------------------------------

const tailWindow = 512 * 1024

// tailLines returns up to the last n lines of the file at path. When privileged
// is set and a direct read is denied, it falls back to `sudo cat`. Errors yield
// an empty slice (callers treat missing data as "nothing to correlate").
func tailLines(path string, n int, privileged bool) []string {
	data, err := readTailBytes(path)
	if err != nil {
		if privileged {
			if out, serr := exec.Command("sudo", "cat", path).Output(); serr == nil {
				data = out
			} else {
				return nil
			}
		} else {
			return nil
		}
	}
	lines := splitLines(data)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// readTailBytes reads up to the final tailWindow bytes of a file.
func readTailBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	var offset int64
	if size > tailWindow {
		offset = size - tailWindow
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// splitLines splits raw bytes into lines, dropping a single trailing newline so a
// well-formed log does not yield a spurious empty final entry.
func splitLines(data []byte) []string {
	s := string(data)
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// -------------------------------------------------------------------------
// Live
// -------------------------------------------------------------------------

// Live tails the buffer, command, and keystroke logs together (via sudo, since
// keys.log is root-owned) and colourises each line by plane: BUFFER -> magenta
// BUF, EXEC -> yellow, KEY -> dim, DEVICE_* -> red. BUFFER is zsh-only; EXEC
// covers every shell (bash/zsh/fish). It runs until interrupted (Ctrl-C).
func Live() error {
	pal := colors()
	fmt.Fprintf(os.Stdout, "live unified tail -- Ctrl-C to stop. %sBUF%s=prompt %sEXEC%s=command %sKEY%s=keystroke\n",
		pal.M, pal.N, pal.Y, pal.N, pal.Dim, pal.N)

	p := resolvePaths()
	if _, err := os.Stat(p.buflog); os.IsNotExist(err) {
		fmt.Fprintf(os.Stdout, "%snote%s: %s does not exist yet -- if the store is set up, run `sudo linaudit store up` to mount %s. Tailing anyway; lines appear once logging starts.\n",
			pal.Y, pal.N, p.buflog, "/var/log/linaudit")
	}
	// Mirror the bash: `sudo sh -c "tail -n0 -F BUFLOG CMDLOG KEYLOG 2>/dev/null"`.
	script := fmt.Sprintf("tail -n0 -F %s %s %s 2>/dev/null",
		shellQuote(p.buflog), shellQuote(p.cmdlog), shellQuote(keyLog))
	cmd := exec.Command("sudo", "sh", "-c", script)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("live tail pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start live tail: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "\tBUFFER\t"):
			// Everything after the final "\tBUFFER\t" separator.
			idx := strings.LastIndex(line, "\tBUFFER\t")
			rest := line[idx+len("\tBUFFER\t"):]
			fmt.Fprintf(os.Stdout, "%sBUF%s %s\n", pal.M, pal.N, rest)
		case strings.Contains(line, "\tEXEC\t"):
			idx := strings.LastIndex(line, "\tEXEC\t")
			rest := line[idx+len("\tEXEC\t"):]
			fmt.Fprintf(os.Stdout, "%sEXEC%s %s\n", pal.Y, pal.N, rest)
		case strings.Contains(line, "\tKEY\t"):
			fmt.Fprintf(os.Stdout, "%sKEY %s%s\n", pal.Dim, line, pal.N)
		case strings.Contains(line, "DEVICE_ADDED") || strings.Contains(line, "DEVICE_REMOVED"):
			fmt.Fprintf(os.Stdout, "%s%s%s\n", pal.R, line, pal.N)
		}
	}
	// Wait reaps the child; interruption (Ctrl-C) surfaces here and is benign.
	_ = cmd.Wait()
	return nil
}

// shellQuote single-quotes a path for safe embedding in the `sh -c` tail script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// -------------------------------------------------------------------------
// Open
// -------------------------------------------------------------------------

// Open launches the dashboard URL in a browser, detached from this process. The
// browser is $BROWSER if set, otherwise the first of xdg-open, brave, firefox,
// chromium found on PATH. The child is started with setsid so it survives the
// CLI exiting; the call returns immediately without waiting.
func Open() error {
	browser, err := findBrowser()
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	if _, lerr := exec.LookPath("setsid"); lerr == nil {
		cmd = exec.Command("setsid", browser, dashboardURL)
	} else {
		cmd = exec.Command(browser, dashboardURL)
	}
	// Detach stdio so the browser does not tie up the terminal.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch browser %q: %w", browser, err)
	}
	// Do not Wait: the browser runs independently. Release the child handle.
	go func() { _ = cmd.Wait() }()

	fmt.Fprintf(os.Stdout, "opening %s\n", dashboardURL)
	return nil
}

// findBrowser resolves the browser to launch: $BROWSER (verbatim, used as-is even
// if not on PATH) then the first available of xdg-open, brave, firefox, chromium.
func findBrowser() (string, error) {
	if b := strings.TrimSpace(os.Getenv("BROWSER")); b != "" {
		return b, nil
	}
	for _, name := range []string{"xdg-open", "brave", "firefox", "chromium"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no browser found (set $BROWSER or install xdg-open/brave/firefox/chromium)")
}

// -------------------------------------------------------------------------
// Menu
// -------------------------------------------------------------------------

// Menu runs the interactive control panel: it prints Status and a menu, reads a
// choice from stdin, performs the corresponding toggle/view/analysis, and loops
// until the user quits. Toggles flip the layer's current state.
func Menu() error {
	pal := colors()
	reader := bufio.NewReader(os.Stdin)

	for {
		clearScreen()
		if err := Status(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "  %stoggles%s   [1] shell   [2] input   [3] auditd\n", pal.Bold, pal.N)
		fmt.Fprintf(os.Stdout, "  %sview%s      [4] buffer  [5] exec  [6] keystrokes  [7] devices  [8] usb\n", pal.Bold, pal.N)
		fmt.Fprintf(os.Stdout, "  %sanalyze%s   [9] correlate   [0] live tail\n", pal.Bold, pal.N)
		fmt.Fprintln(os.Stdout, "            [q] quit")
		fmt.Fprint(os.Stdout, "  > ")

		choice, err := readChoice(reader)
		if err != nil {
			// EOF on stdin (e.g. non-interactive) ends the loop cleanly.
			fmt.Fprintln(os.Stdout)
			return nil
		}
		fmt.Fprintln(os.Stdout)

		p := resolvePaths()
		switch choice {
		case "1":
			if shellOn(p) {
				reportToggle(disableShell(p))
			} else {
				reportToggle(enableShell(p))
			}
		case "2":
			if svcActive(inputService) {
				reportToggle(disableService(inputService))
			} else {
				reportToggle(enableService(inputService, false))
			}
		case "3":
			if svcActive(auditService) {
				reportToggle(disableService(auditService))
			} else {
				reportToggle(enableService(auditService, true))
			}
		case "4":
			runView("buffer")
		case "5":
			runView("exec")
		case "6":
			runView("keys")
		case "7":
			runView("devices")
		case "8":
			runView("usb")
		case "9":
			var buf bytes.Buffer
			if err := reportTo(&buf, "25"); err != nil {
				fmt.Fprintf(os.Stderr, "linaudit: %v\n", err)
			}
			if err := page(bytes.NewReader(buf.Bytes())); err != nil {
				fmt.Fprintf(os.Stderr, "linaudit: %v\n", err)
			}
		case "0":
			if err := Live(); err != nil {
				fmt.Fprintf(os.Stderr, "linaudit: %v\n", err)
			}
		case "q", "Q":
			return nil
		}
	}
}

// runView executes a Logs view from the menu and surfaces any error to stderr.
func runView(which string) {
	if err := Logs(which); err != nil {
		fmt.Fprintf(os.Stderr, "linaudit: %v\n", err)
	}
}

// reportToggle prints a toggle error to stderr but never aborts the menu loop.
func reportToggle(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "linaudit: %v\n", err)
	}
}

// readChoice reads a single line of input and returns the trimmed value. The bash
// original read a single keypress; reading a whole line is the documented Go
// behaviour and is friendlier without raw-mode terminal handling.
func readChoice(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

// clearScreen clears the terminal between menu iterations when interactive. The
// escape sequence is harmless to skip when not on a TTY.
func clearScreen() {
	if isTTY() {
		fmt.Fprint(os.Stdout, "\x1b[2J\x1b[H")
	}
}
