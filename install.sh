#!/bin/sh
# LinAudit installer -- distro-agnostic (any systemd Linux). Builds the single
# static binary, installs it plus the systemd units and system configs, detects
# the monitored user, optionally initialises the encrypted store, enables the
# services, and finishes with `linaudit doctor`.
#
# Usage:  sudo sh install.sh
# Env:    LINAUDIT_USER=<name>   pin the monitored account (else auto-detected)
#         SKIP_STORE=1           do not create/enable the encrypted store
#         SKIP_GEOIP=1           do not download the offline GeoIP DB
set -eu

REPO="$(cd "$(dirname "$0")" && pwd -P)"
BIN=/usr/local/bin/linaudit
ENVFILE=/etc/linaudit/linaudit.env

die() { echo "install: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo sh install.sh)"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required for the services"

# --- detect the monitored (human) account ---
detect_user() {
  if [ -n "${LINAUDIT_USER:-}" ]; then echo "$LINAUDIT_USER"; return; fi
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then echo "$SUDO_USER"; return; fi
  awk -F: '($3>=1000 && $3<=60000 && $7 !~ /(nologin|false)$/ && $7!=""){print $1}' /etc/passwd
}
USER_LINES="$(detect_user)"
USERCOUNT="$(printf '%s\n' "$USER_LINES" | grep -c .)"
[ "$USERCOUNT" -eq 1 ] || die "could not uniquely determine the monitored user (found: ${USER_LINES:-none}). Re-run with LINAUDIT_USER=<name>."
LAUSER="$USER_LINES"
id "$LAUSER" >/dev/null 2>&1 || die "user '$LAUSER' does not exist"
echo "==> monitored user: $LAUSER"

# --- build the static binary (or use a prebuilt ./linaudit) ---
if command -v go >/dev/null 2>&1; then
  echo "==> building $BIN"
  ( cd "$REPO" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tmp/linaudit.build ./cmd/linaudit )
  install -m755 /tmp/linaudit.build "$BIN"; rm -f /tmp/linaudit.build
elif [ -x "$REPO/linaudit" ]; then
  echo "==> installing prebuilt $REPO/linaudit"
  install -m755 "$REPO/linaudit" "$BIN"
else
  die "Go toolchain not found and no prebuilt ./linaudit; install Go or run 'make build' first"
fi

# --- env file so the root services resolve the user deterministically ---
install -d -m700 /etc/linaudit
printf 'LINAUDIT_USER=%s\n' "$LAUSER" > "$ENVFILE"
chmod 600 "$ENVFILE"

# --- systemd units ---
echo "==> installing systemd units"
install -m644 "$REPO/storage/linaudit-store.service"  /etc/systemd/system/linaudit-store.service
install -m644 "$REPO/inputmon/linaudit-input.service" /etc/systemd/system/linaudit-input.service
install -m644 "$REPO/web/linaudit-web.service"        /etc/systemd/system/linaudit-web.service

# --- auditd rules + udev + logrotate (templated) + brave policy ---
echo "==> installing system configs"
if [ -d /etc/audit/rules.d ]; then install -m640 "$REPO/system/linaudit.rules" /etc/audit/rules.d/linaudit.rules; fi
install -d -m755 /etc/udev/rules.d
install -m644 "$REPO/system/97-linaudit.rules" /etc/udev/rules.d/97-linaudit.rules
install -d -m755 /etc/logrotate.d
sed "s/__LINAUDIT_USER__/$LAUSER/g" "$REPO/system/linaudit.logrotate" > /etc/logrotate.d/linaudit
chmod 644 /etc/logrotate.d/linaudit
if [ -d /etc/brave/policies/managed ] || mkdir -p /etc/brave/policies/managed 2>/dev/null; then
  install -m644 "$REPO/system/linaudit-dashboard.json" /etc/brave/policies/managed/linaudit-dashboard.json 2>/dev/null || true
fi

# --- offline GeoIP DB (optional) ---
if [ "${SKIP_GEOIP:-0}" != 1 ]; then
  echo "==> fetching offline GeoIP country + ASN/org DBs"
  sh "$REPO/data/fetch-geoip.sh" || echo "install: GeoIP/ASN fetch failed (network?); the map + owner classification degrade gracefully"
fi

systemctl daemon-reload

# --- encrypted store + services ---
if [ "${SKIP_STORE:-0}" != 1 ]; then
  if [ ! -e /var/lib/linaudit/store.img ]; then
    echo "==> creating the encrypted store (linaudit store init)"
    "$BIN" store init
  fi
  systemctl enable --now linaudit-store.service
  systemctl enable --now linaudit-input.service
  systemctl enable --now linaudit-web.service
fi

# --- auditd (if installed) ---
if systemctl list-unit-files auditd.service --no-legend 2>/dev/null | grep -q auditd; then
  command -v augenrules >/dev/null 2>&1 && augenrules --load >/dev/null 2>&1 || true
  systemctl enable --now auditd.service 2>/dev/null || true
  command -v auditctl >/dev/null 2>&1 && auditctl -e 1 >/dev/null 2>&1 || true
else
  echo "install: auditd not installed -- exec/uinput/USB audit plane is off (optional; see README)"
fi

# --- audit subj_ctx kernel-log flood mitigation (ONLY on affected kernels) ---
# Some kernels (observed: 7.0.x Manjaro) flood the kernel ring buffer with
# "audit: error in audit_log_subj_ctx" because audit_log_subj_ctx() cannot render
# the AppArmor subject label for unconfined tasks, the failure mode is PRINTK, and
# the kernel rejects every auditctl AUDIT_SET so it cannot be silenced with
# `auditctl -f 0`. We install a printk-ratelimit drop-in ONLY when this exact
# condition is detected (re-asserting the current failure mode is a no-op on
# healthy kernels and errors on affected ones), so healthy hosts are never masked.
if command -v auditctl >/dev/null 2>&1 && systemctl is-active --quiet auditd.service 2>/dev/null; then
  fmode=$(auditctl -s 2>/dev/null | awk '/^failure/{print $2}')
  apparmor=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)
  if [ "$fmode" = "1" ] && [ "$apparmor" = "Y" ] && ! auditctl -f "$fmode" >/dev/null 2>&1; then
    echo "==> affected kernel detected (audit reconfig rejected + AppArmor subj_ctx flood): installing printk-ratelimit mitigation"
    install -m644 "$REPO/system/99-linaudit-audit-quiet.conf" /etc/sysctl.d/99-linaudit-audit-quiet.conf
    sysctl -p /etc/sysctl.d/99-linaudit-audit-quiet.conf >/dev/null 2>&1 || true
  fi
fi

command -v udevadm >/dev/null 2>&1 && udevadm control --reload-rules 2>/dev/null || true

# --- shell hooks (for the monitored user) ---
# Install the hook for every supported shell that is present, so whichever shell
# the user launches is covered. The shells share one log set and one "disabled"
# flag. zsh captures unexecuted prompt text too (its line editor allows it);
# bash and fish capture executed commands. fish auto-loads from conf.d (no rc edit).
HOMEDIR="$(getent passwd "$LAUSER" | cut -d: -f6)"
if [ -n "$HOMEDIR" ]; then
  LAGROUP="$(id -gn "$LAUSER" 2>/dev/null || echo "$LAUSER")"
  uinstall_d() { install -d -o "$LAUSER" -g "$LAGROUP" -m755 "$1"; }
  uinstall_f() { install -o "$LAUSER" -g "$LAGROUP" -m600 "$1" "$2"; }
  # wire_rc RCFILE 'source line' MARKER -- append a guarded source line once.
  wire_rc() {
    if ! grep -q "$3" "$1" 2>/dev/null; then
      printf '\n# LinAudit\n%s\n' "$2" >> "$1"
      chown "$LAUSER:$LAGROUP" "$1" 2>/dev/null || true
    fi
  }

  WIRED=""
  if command -v zsh >/dev/null 2>&1; then
    uinstall_d "$HOMEDIR/.config/zsh"
    uinstall_f "$REPO/shell/linaudit.zsh" "$HOMEDIR/.config/zsh/linaudit.zsh"
    wire_rc "$HOMEDIR/.zshrc" '[[ -f ~/.config/zsh/linaudit.zsh ]] && source ~/.config/zsh/linaudit.zsh' 'linaudit.zsh'
    WIRED="$WIRED zsh"
  fi
  if command -v bash >/dev/null 2>&1; then
    uinstall_d "$HOMEDIR/.config/bash"
    uinstall_f "$REPO/shell/linaudit.bash" "$HOMEDIR/.config/bash/linaudit.bash"
    wire_rc "$HOMEDIR/.bashrc" '[ -f ~/.config/bash/linaudit.bash ] && . ~/.config/bash/linaudit.bash' 'linaudit.bash'
    WIRED="$WIRED bash"
  fi
  if command -v fish >/dev/null 2>&1; then
    uinstall_d "$HOMEDIR/.config/fish/conf.d"
    uinstall_f "$REPO/shell/linaudit.fish" "$HOMEDIR/.config/fish/conf.d/linaudit.fish"
    WIRED="$WIRED fish"
  fi

  if [ -n "$WIRED" ]; then
    echo "install: shell hooks installed for:$WIRED; $LAUSER should open a new terminal"
  else
    echo "install: no supported shell (bash/zsh/fish) found; the shell prompt/command plane is not wired"
  fi
fi

echo
echo "==> install complete; running diagnostic"
"$BIN" doctor || true
echo
echo "Dashboard: http://127.0.0.1:8799/  (first visit sets the password)"
