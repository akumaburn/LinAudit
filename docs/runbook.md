# LinAudit

A three-plane monitor built to catch "a command appeared in my terminal that I
did not type" -- including the case where the command is never executed (so
ordinary history/exec auditing would miss it). Logs are encrypted at rest and the
web dashboard is password-protected.

## The three planes

| Plane | Component | Log (inside encrypted store) | Owner |
|-------|-----------|------------------------------|-------|
| Prompt text (even unexecuted, zsh only) + executed commands (bash/zsh/fish) | shell hooks (`~/.config/{zsh/linaudit.zsh,bash/linaudit.bash,fish/conf.d/linaudit.fish}`) | `/var/log/linaudit/shell/{buffer,commands}.log` | you |
| Physical/virtual keystroke source | `linaudit-input.service` | `/var/log/linaudit/input/keys.log` | root |
| Executions, `/dev/uinput` access, USB add/remove | `auditd` + udev rule | `ausearch -k cmd_exec` / `-k uinput_inject`; `journalctl -t linaudit-usb` | root |

Backward-compat symlinks point the old paths (`/var/log/linaudit/input/keys.log`,
`~/.local/share/linaudit/{buffer,commands}.log`) at the encrypted store.

Shell coverage: the prompt/command plane has a hook per common shell, all writing
the same `commands.log`/`buffer.log` in one format and all gated by one shared
`~/.local/share/linaudit/disabled` flag (so `linaudit disable shell` or the
dashboard toggle stops every shell at once). Only zsh can record *unexecuted*
prompt text (`buffer.log`) -- it is the one shell whose line editor exposes a
per-keystroke hook. bash and fish record *executed* commands (`commands.log`)
via their preexec equivalents (bash logs at command completion since it has no
pre-execution full-line hook; fish and zsh log just before execution). For
bash/fish the "typed vs pasted/injected" call comes from correlating each
command against `keys.log` (the shell-agnostic keystroke plane), exactly as
below -- a command with no preceding `KEY` burst was pasted or injected.

## Encryption at rest (LUKS2 + TPM)

- All logs live in a LUKS2 container `/var/lib/linaudit/store.img`
  (aes-xts-256), mounted at `/var/log/linaudit` by `linaudit-store.service`.
- The container key is **sealed to this machine's TPM** (`systemd-creds`,
  host+tpm2) at `/etc/linaudit/store.key.cred`; it is released automatically at
  boot and piped straight into `cryptsetup` -- the raw key is never written to
  disk in plaintext.
- **Protects against:** a pulled/stolen disk, booting another OS, and
  backups/btrfs (timeshift) snapshots -- all see only ciphertext.
- **Does NOT protect against:** a live root attacker on this running machine
  (the key is in the kernel keyring while mounted). For whole-disk protection use
  full-disk encryption (LUKS on root).
- `linaudit-input.service` and `linaudit-web.service` have `Requires=linaudit-store.service`,
  so if the store cannot be unlocked, they refuse to start rather than writing
  plaintext anywhere.

## Dashboard password

- First visit shows a **setup page** to choose a password (min 8 chars).
- Hash: `scrypt` (salted), stored root-only at `/var/lib/linaudit/auth.json`.
- Login issues an in-memory session (HttpOnly, SameSite=Strict cookie, 12h).
  Sessions are cleared on service restart/reboot -> you log in again.
- 5 wrong attempts -> 30s lockout. Localhost-only, plus per-load CSRF token and
  Host/Origin checks (see the `web/server.go` header).
- Reset/forgot password: `sudo rm /var/lib/linaudit/auth.json && sudo systemctl
  restart linaudit-web` -> next visit shows setup again.

## Dashboard

`linaudit` (CLI panel) or the web UI at **http://127.0.0.1:8799/** (Brave
homepage). Web actions: live/pause auto-refresh, per-tab log views (newest first),
correlated timeline, enable/disable each layer, logout.

```
linaudit status | enable LAYER | disable LAYER | logs WHICH | report [N] | live | open
```

(`linaudit` is a single static binary; `linaudit web` runs the dashboard server and
`linaudit input` / `linaudit store up|down|init` are the service entry points.)

## How to read the next occurrence

Each `KEY` record in `keys.log` carries a trailing **bus** field classified from
the device's `phys` at open time: `wired` (USB / PS-2), `wireless` (Bluetooth),
`virtual` (uinput / no topology -- the software-injection signature), or `other`.
The web dashboard hides `wired` keystrokes by default (both the Logs > keystrokes
tab and the Timeline), so the routine physical-keyboard noise is suppressed and
only wireless / virtual / unidentified sources are shown, each tagged with its
bus. A "show wired" toggle (or the `w` key) reveals everything; the CLI
(`linaudit report` / `logs keys`) always shows the full stream.

Run `linaudit report 25` (or the timeline panel) and read around the moment:

- Prompt text **grows one char at a time**, each `KEY` from a real keyboard
  (`AT Translated Set 2 keyboard`, `USB Keyboard`, `HP HP Gaming Keyboard II`)
  -> physically typed.
- Prompt text appears **all at once** after a `KEY` from `Logitech G604`
  -> a mouse macro / HID event (e.g. `BTN_MIDDLE` = middle-click paste).
- Prompt text appears **all at once with NO `KEY` events** -> a paste or Wayland
  virtual-keyboard injection.
- A `DEVICE_ADDED` for an unknown/virtual device, or a `uinput_inject` audit hit
  (`sudo ausearch -k uinput_inject`), with keystrokes from it -> software
  keystroke injector (strongest attack signal).
- Unexpected `linaudit-usb` journal entry near the event -> investigate that USB
  device (possible BadUSB).

## Network owners (known vs unknown peers)

The network panel resolves every remote peer to its **ASN and organization** from
an offline database (`/usr/local/share/linaudit/geoip/asn-ipv{4,6}.csv`, fetched
by `data/fetch-geoip.sh`) and buckets it into a colour-coded category shown in the
connection table's *owner* column, with a legend strip giving the known-vs-unknown
breakdown (click a category to filter):

- `corp` -- big tech / enterprise (Microsoft, Apple, Google, Meta, ...).
- `cloud` -- cloud / hosting / VPS (AWS, Azure, GCP, Hetzner, DigitalOcean, ...).
- `cdn` -- content-delivery / edge (Cloudflare, Akamai, Fastly, ...).
- `gov` -- government / military (best-effort; see caveat).
- `telecom` -- consumer ISPs / carriers (Comcast, Vodafone, ...).
- `unknown` -- no ASN match at all; `other` -- ASN resolved but not a named
  category (its org name is still shown).

Forensic use: most normal traffic is `corp` / `cloud` / `cdn`. A connection to an
`unknown` network, an unexpected `gov` peer, or a long-lived flow to a bare VPS
(`other` / a small hosting ASN) next to a suspicious shell or keystroke event is
worth investigating. The owner is shown alongside the country flag and reverse
DNS, so "US + Cloudflare + cdn" reads very differently from "unknown country +
unknown ASN".

Caveat -- the classification is heuristic and offline. Cloud regions inherit their
parent's category (Azure shows as `corp` because its AS-name is "Microsoft
Corporation"; AWS as `cloud`). **Government detection in particular is best-effort**:
it matches government/military markers in the AS-name plus a small curated ASN list,
deliberately conservative to avoid false positives (e.g. "Federal Express",
"Salvation Army", "Governors State University" are *not* flagged), so it will miss
many public networks and may occasionally mislabel one. Treat `gov` as a hint, not
proof. The provider/gov tables live in `web/netmon/orgcat.go` and are trivial to
extend.

## Services / recovery

- Units: `linaudit-store.service` (unlock+mount) -> `linaudit-input.service`,
  `linaudit-web.service`; plus `auditd.service`. All enabled at boot, ordered with
  no cycle.
- Logs rotate daily, 14 days, inside the encrypted store
  (`/etc/logrotate.d/linaudit`).
- **If the TPM is cleared / firmware-reset:** the sealed key is unrecoverable, so
  `linaudit-store.service` fails and the existing encrypted logs are lost by design.
  Re-initialise a fresh store with `sudo linaudit store init` (creates a new
  container + reseals the key to the TPM).
- Re-test the software-injection detector any time, from a checkout of the repo:
  `sudo go run ./test/inject` (or build it once with `go build -o inject ./test/inject`
  and run `sudo ./inject`). It creates a uinput virtual keyboard and emits one KEY_F20.

## Kernel audit log flood (`error in audit_log_subj_ctx`)

On some kernels (observed on 7.0.x Manjaro) the kernel ring buffer / `dmesg`
floods with:

```
audit: error in audit_log_subj_ctx
audit_panic: NN callbacks suppressed
```

This is a kernel-side regression, not a LinAudit fault. `audit_log_subj_ctx()`
fails to render the optional `subj=` label for AppArmor-*unconfined* tasks; because
the audit failure mode is PRINTK, every failure is logged. The volume tracks
audited-syscall volume 1:1, so LinAudit's system-wide `execve` rule makes it
constant. The audit *records themselves are intact* -- only the cosmetic `subj=`
field is missing -- so detection is unaffected.

The normal silence switch is `auditctl -f 0` (failure mode = silent). On the
affected kernels **every `auditctl` `AUDIT_SET` is rejected** (`-f`, `-b`, `-r` all
fail; only `auditd`'s pid registration succeeds), so the failure mode cannot be
changed at runtime and `-f 0` cannot be placed in the rules file either (it would
break `augenrules --load`). Confirm with: `sudo auditctl -s` (`failure 1`,
`backlog 0`, `lost 0`) and `sudo auditctl -f 1` returning "error while processing
parameters".

- **Mitigation (shipped):** `system/99-linaudit-audit-quiet.conf` throttles the
  benign message at the printk layer (`audit_panic()` honors `printk_ratelimit()`).
  `install.sh` installs it automatically **only on hosts that exhibit the defect**
  (so healthy hosts are never masked); `linaudit doctor` reports the condition and
  whether the mitigation is active. Apply manually with:
  `sudo install -m644 system/99-linaudit-audit-quiet.conf /etc/sysctl.d/ && sudo sysctl --system`.
- It only affects legacy `printk_ratelimit()` callers, not the per-callsite
  `pr_*_ratelimited()` users, so collateral on other kernel logging is small.
- **Real fix:** boot a kernel without the regression (where `auditctl -f 0` works
  again); then remove the drop-in and run `sudo sysctl --system`.
