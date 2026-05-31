// Package storage manages the TPM-sealed, LUKS2-encrypted audit log store.
//
// It is a faithful Go port of storage/secure-mount.sh (up/down) and
// storage/secure-init.sh (init). The LUKS key never touches persistent disk in
// plaintext: on Up() it is released by systemd-creds from the TPM and piped
// straight into cryptsetup; on Init() the raw key lives only on tmpfs (/run)
// before being sealed and shredded.
package storage

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"linaudit/identity"
)

const (
	// IMG is the backing file that holds the LUKS2 container.
	IMG = "/var/lib/linaudit/store.img"
	// CRED is the TPM-sealed credential holding the LUKS key.
	CRED = "/etc/linaudit/store.key.cred"
	// MAP is the device-mapper name for the opened LUKS volume.
	MAP = "linaudit_store"
	// MNT is the mountpoint for the decrypted audit log filesystem.
	MNT = "/var/log/linaudit"
	// keyTmp is the tmpfs-only path used to stage the raw key during Init().
	keyTmp = "/run/audit-keytmp"
	// imgSize is the size of the backing image (1 GiB), matching SIZE=1G.
	imgSize = 1 << 30
)

// mapperPath is the /dev/mapper path for the opened LUKS volume.
func mapperPath() string {
	return "/dev/mapper/" + MAP
}

// exists reports whether a filesystem path exists (file, dir, or device node).
func exists(path string) bool {
	_, err := os.Stat(path) // Stat follows symlinks, matching POSIX `[ -e ]`
	return err == nil
}

// Up unlocks (TPM-sealed key) and mounts the encrypted audit log store.
//
// Port of up() in secure-mount.sh:
//
//	if [ ! -e "/dev/mapper/$MAP" ]; then
//	  systemd-creds decrypt --name=auditstore "$CRED" - \
//	    | cryptsetup open --type luks2 --key-file=- "$IMG" "$MAP"
//	fi
//	mkdir -p "$MNT"
//	mountpoint -q "$MNT" || mount "/dev/mapper/$MAP" "$MNT"
//	mkdir -p "$MNT/input" "$MNT/shell"
//	chown root:root "$MNT/input";       chmod 700 "$MNT/input"
//	chown "$OWNER:$OWNER" "$MNT/shell"; chmod 700 "$MNT/shell"
func Up() error {
	if err := preflight("systemd-creds", "cryptsetup", "mount"); err != nil {
		return err
	}
	if !exists(mapperPath()) {
		if err := decryptAndOpen(); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(MNT, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", MNT, err)
	}

	mounted, err := isMountpoint(MNT)
	if err != nil {
		return fmt.Errorf("mountpoint check %s: %w", MNT, err)
	}
	if !mounted {
		if err := run("mount", mapperPath(), MNT); err != nil {
			return err
		}
	}

	inputDir := filepath.Join(MNT, "input")
	shellDir := filepath.Join(MNT, "shell")

	if err := os.MkdirAll(inputDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", inputDir, err)
	}
	if err := os.MkdirAll(shellDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", shellDir, err)
	}

	// input dir: root:root, 0700.
	if err := os.Chown(inputDir, 0, 0); err != nil {
		return fmt.Errorf("chown %s: %w", inputDir, err)
	}
	if err := os.Chmod(inputDir, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", inputDir, err)
	}

	// shell dir: 0700 always; ownership best-effort. The store MUST mount even on
	// a host without the monitored account, so an unresolved user only leaves the
	// dir root-owned (still 0700) with a warning -- it never fails the mount.
	if err := os.Chmod(shellDir, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", shellDir, err)
	}
	if uid, gid, ok := identity.IDs(); ok {
		if err := os.Chown(shellDir, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", shellDir, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "linaudit store: monitored user unresolved (set LINAUDIT_USER); leaving %s root-owned (0700)\n", shellDir)
	}

	return nil
}

// decryptAndOpen reproduces the single shell pipeline:
//
//	systemd-creds decrypt --name=auditstore CRED - | cryptsetup open --type luks2 --key-file=- IMG MAP
//
// The decrypted key is streamed directly from systemd-creds into cryptsetup's
// stdin and never written to disk. Both processes are started, then both are
// waited on; an error from either fails the operation.
func decryptAndOpen() error {
	decrypt := exec.Command("systemd-creds", "decrypt", "--name=auditstore", CRED, "-")
	open := exec.Command("cryptsetup", "open", "--type", "luks2", "--key-file=-", IMG, MAP)

	pipe, err := decrypt.StdoutPipe()
	if err != nil {
		return fmt.Errorf("systemd-creds stdout pipe: %w", err)
	}
	open.Stdin = pipe

	// Surface diagnostics on the parent's standard streams, matching shell behavior.
	decrypt.Stderr = os.Stderr
	open.Stdout = os.Stdout
	open.Stderr = os.Stderr

	if err := open.Start(); err != nil {
		return fmt.Errorf("start cryptsetup open: %w", err)
	}
	if err := decrypt.Start(); err != nil {
		// cryptsetup is already running; close its stdin so it does not hang,
		// then reap it before returning.
		pipe.Close()
		_ = open.Wait()
		return fmt.Errorf("start systemd-creds decrypt: %w", err)
	}

	// Wait for the producer first so its stdout (the pipe write end) is closed,
	// giving cryptsetup an EOF on stdin.
	decryptErr := decrypt.Wait()
	openErr := open.Wait()

	if decryptErr != nil {
		return fmt.Errorf("systemd-creds decrypt: %w", decryptErr)
	}
	if openErr != nil {
		return fmt.Errorf("cryptsetup open: %w", openErr)
	}
	return nil
}

// Down unmounts the store and closes the LUKS mapping.
//
// Port of down() in secure-mount.sh -- both steps tolerate errors:
//
//	umount "$MNT" 2>/dev/null || true
//	if [ -e "/dev/mapper/$MAP" ]; then cryptsetup close "$MAP" || true; fi
func Down() error {
	// Ignore umount error (may already be unmounted), matching the shell.
	_ = run("umount", MNT)

	if exists(mapperPath()) {
		// Ignore close error, matching the shell.
		_ = run("cryptsetup", "close", MAP)
	}
	return nil
}

// Init performs the one-time creation of the TPM-sealed LUKS log store.
// Idempotent: if the backing image already exists it prints a notice and
// returns nil. Port of secure-init.sh.
func Init() error {
	if err := os.MkdirAll("/var/lib/linaudit", 0700); err != nil {
		return fmt.Errorf("mkdir /var/lib/linaudit: %w", err)
	}
	if err := os.MkdirAll("/etc/linaudit", 0700); err != nil {
		return fmt.Errorf("mkdir /etc/linaudit: %w", err)
	}
	// Ensure permissions on the parent dirs match `chmod 700` in the script,
	// in case MkdirAll found them already present with other modes.
	if err := os.Chmod("/var/lib/linaudit", 0700); err != nil {
		return fmt.Errorf("chmod /var/lib/linaudit: %w", err)
	}
	if err := os.Chmod("/etc/linaudit", 0700); err != nil {
		return fmt.Errorf("chmod /etc/linaudit: %w", err)
	}

	if exists(IMG) {
		fmt.Printf("store already exists: %s (leaving as-is)\n", IMG)
		return nil
	}

	if err := preflight("cryptsetup", "mkfs.ext4", "systemd-creds"); err != nil {
		return err
	}

	// Create the backing image truncated to 1 GiB, mode 0600.
	if err := createImage(); err != nil {
		return err
	}

	// Stage a fresh 64-byte random key on tmpfs only, mode 0600.
	if err := writeKey(); err != nil {
		return err
	}
	// Best-effort cleanup of the staged key in all subsequent failure paths.
	defer shred(keyTmp)

	if err := run("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--key-file="+keyTmp, IMG); err != nil {
		return err
	}
	if err := run("cryptsetup", "open", "--type", "luks2", "--key-file="+keyTmp, IMG, MAP); err != nil {
		return err
	}
	if err := run("mkfs.ext4", "-q", "-L", "linaudit", mapperPath()); err != nil {
		// Attempt to close the mapping before returning so we do not leak it.
		_ = run("cryptsetup", "close", MAP)
		return err
	}
	if err := run("cryptsetup", "close", MAP); err != nil {
		return err
	}

	// Seal the key. With a TPM present, bind it (host+tpm2) deterministically;
	// without one, --with-key=auto would SILENTLY fall back to host-only wrapping,
	// so make that explicit and warn rather than implying TPM protection exists.
	keyMode := "--with-key=host+tpm2"
	if !tpmPresent() {
		keyMode = "--with-key=host"
		fmt.Fprintln(os.Stderr, "linaudit store: no TPM2 device (/dev/tpmrm0); sealing the key to the HOST only (no TPM binding).")
	}
	if err := run("systemd-creds", "encrypt", "--name=auditstore", keyMode, keyTmp, CRED); err != nil {
		return err
	}
	if err := os.Chmod(CRED, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", CRED, err)
	}

	// shred via defer runs after this point as well; remove eagerly so the OK
	// summary reflects the final, key-free state.
	shred(keyTmp)

	fmt.Printf("OK: created %s (LUKS2) and sealed key -> %s\n", IMG, CRED)
	printListing(IMG, CRED)
	return nil
}

// createImage creates IMG, truncates it to imgSize, and sets mode 0600.
// Mirrors: truncate -s 1G IMG; chmod 600 IMG.
func createImage() error {
	f, err := os.OpenFile(IMG, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w", IMG, err)
	}
	if err := f.Truncate(imgSize); err != nil {
		f.Close()
		return fmt.Errorf("truncate %s: %w", IMG, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", IMG, err)
	}
	// Enforce 0600 explicitly in case the file pre-existed with another mode
	// (OpenFile mode is only applied at creation, subject to umask).
	if err := os.Chmod(IMG, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", IMG, err)
	}
	return nil
}

// writeKey writes 64 cryptographically-random bytes to keyTmp with mode 0600.
// Mirrors: head -c 64 /dev/urandom > KEY; chmod 600 KEY.
func writeKey() error {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	f, err := os.OpenFile(keyTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w", keyTmp, err)
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", keyTmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", keyTmp, err)
	}
	// Defend the at-rest mode against umask, matching `chmod 600`.
	if err := os.Chmod(keyTmp, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", keyTmp, err)
	}
	return nil
}

// shred best-effort overwrites the file with zeros, then removes it. Mirrors
// `shred -u KEY 2>/dev/null || rm -f KEY`: any failure is ignored so cleanup is
// never fatal.
func shred(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		// Nothing to shred (or unreadable); still attempt removal.
		_ = os.Remove(path)
		return
	}
	if size := fi.Size(); size > 0 {
		if f, ferr := os.OpenFile(path, os.O_WRONLY, 0); ferr == nil {
			zeros := make([]byte, 4096)
			var written int64
			for written < size {
				n := int64(len(zeros))
				if remaining := size - written; remaining < n {
					n = remaining
				}
				if _, werr := f.Write(zeros[:n]); werr != nil {
					break
				}
				written += n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

// printListing mirrors `ls -l IMG CRED` -- a non-fatal summary. We do not shell
// out for cosmetics; instead format size and mode from os.Stat. Any stat error
// is silently skipped (matching that the script's final ls is informational).
func printListing(paths ...string) {
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Printf("%s %10d %s\n", fi.Mode().String(), fi.Size(), p)
	}
}

// run executes a command with an explicit argument array (no shell), wiring its
// stdout/stderr to the parent's so cryptsetup/mkfs/systemd-creds diagnostics are
// visible, matching the shell scripts' behavior under `set -eu`.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// preflight verifies the named external tools resolve in PATH, returning one
// aggregated, actionable error instead of a cryptic per-exec ENOENT later.
func preflight(tools ...string) error {
	var missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required tool(s) not found in PATH: %s", strings.Join(missing, ", "))
	}
	return nil
}

// tpmPresent reports whether a TPM2 device node is available for key sealing.
func tpmPresent() bool { return exists("/dev/tpmrm0") || exists("/dev/tpm0") }

// isMountpoint reports whether path is the root of a mounted filesystem,
// reproducing `mountpoint -q`. Primary signal: an entry in /proc/mounts whose
// mount target equals path (after decoding octal escapes). Fallback (if
// /proc/mounts is unavailable): compare the device id of path with that of its
// parent -- they differ only across a mount boundary.
func isMountpoint(path string) (bool, error) {
	clean := filepath.Clean(path)

	if ok, found := mountpointFromProc(clean); found {
		return ok, nil
	}
	// Fail closed: without /proc/mounts we cannot authoritatively decide mount
	// state. Refuse rather than risk a heuristic reporting an UNmounted target as
	// mounted, which would let Up() create plaintext dirs on the bare /var path.
	return false, fmt.Errorf("cannot determine mountpoint status of %s: /proc/mounts unavailable", clean)
}

// mountpointFromProc scans /proc/mounts for an entry mounted exactly at target.
// The boolean result is whether a match was found; found=false means the proc
// source was unavailable and the caller should fall back.
func mountpointFromProc(target string) (match bool, found bool) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Mount lines can be long with many options; allow a generous buffer.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		// fields[1] is the mount target with octal-escaped special chars.
		if unescapeMount(fields[1]) == target {
			return true, true
		}
	}
	if err := sc.Err(); err != nil {
		// Reading failed partway; defer to the dev-id fallback rather than
		// trusting a possibly truncated scan.
		return false, false
	}
	return false, true
}

// unescapeMount decodes the octal escape sequences (\ooo, e.g. \040 for space)
// that the kernel uses in /proc/mounts mount-target fields.
func unescapeMount(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
