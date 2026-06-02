# LinAudit

A three-plane monitor built to catch "a command appeared in my terminal that I
did not type" -- including the case where the command is never executed (so
ordinary history/exec auditing would miss it). Logs are encrypted at rest and the
web dashboard is password-protected.

## The three planes

| Plane | Component | Log (inside encrypted store) | Owner |
|-------|-----------|------------------------------|-------|
| Prompt text (typed or pasted, even unexecuted) + executed commands | zsh hooks (`~/.config/zsh/linaudit.zsh`) | `/var/log/linaudit/shell/{buffer,commands}.log` | you |
| Physical/virtual keystroke source | `linaudit-input.service` | `/var/log/linaudit/input/keys.log` | root |
| Executions, `/dev/uinput` access, USB add/remove | `auditd` + udev rule | `ausearch -k cmd_exec` / `-k uinput_inject`; `journalctl -t linaudit-usb` | root |

Backward-compat symlinks point the old paths (`/var/log/linaudit/input/keys.log`,
`~/.local/share/linaudit/{buffer,commands}.log`) at the encrypted store.

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
