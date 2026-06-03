# LinAudit: capture executed commands in bash into the shared command log, in the
# exact tab-separated format the dashboard and CLI parse. Logs are local and 0600.
# Toggle live via the shared "disabled" flag file (managed by `linaudit`).
#
# Scope note: bash has no per-keystroke line-editor hook (no equivalent of zsh's
# ZLE line-pre-redraw), so this captures only EXECUTED commands -- the unexecuted
# prompt-text plane (buffer.log) is zsh-only. The input-device plane
# (linaudit-input) still records the per-keystroke source for ALL shells, which is
# what lets you tell typed from pasted/injected when correlating against EXEC.
#
# Mechanism: a PROMPT_COMMAND hook reads the just-entered command from the history
# list and logs it once (deduped on the history number, so empty Enter and prompt
# redraws never re-log). The EXEC timestamp is therefore taken when the command
# returns (bash exposes no pre-execution line hook with the full command); the
# command text and ordering relative to keystrokes remain accurate.

# Interactive shells only, and only wire ourselves once.
case $- in *i*) : ;; *) return 0 2>/dev/null || exit 0 ;; esac
[ -n "${_LINAUDIT_BASH_LOADED:-}" ] && return 0
_LINAUDIT_BASH_LOADED=1

_LINAUDIT_DIR="${HOME}/.local/share/linaudit"
_LINAUDIT_CMDLOG="${_LINAUDIT_DIR}/commands.log"
_LINAUDIT_TTY="$(tty 2>/dev/null || echo '?')"
_LINAUDIT_LAST_HIST=""

[ -d "$_LINAUDIT_DIR" ] || { mkdir -p "$_LINAUDIT_DIR" && chmod 700 "$_LINAUDIT_DIR"; }
[ -e "$_LINAUDIT_CMDLOG" ] || { : >> "$_LINAUDIT_CMDLOG" 2>/dev/null && chmod 600 "$_LINAUDIT_CMDLOG"; }

# _linaudit_postcmd runs from PROMPT_COMMAND (parent shell, so its dedup state
# persists). It logs the most recent history entry exactly once.
_linaudit_postcmd() {
  local _rc=$?                                   # preserve the user's exit status
  [ -e "${_LINAUDIT_DIR}/disabled" ] && return $_rc
  local line histno cmd now iso
  line=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null) || return $_rc
  # history prints "   <n>  <command>"; pull the number and the command text.
  if [[ $line =~ ^[[:space:]]*([0-9]+)[[:space:]]+(.*)$ ]]; then
    histno=${BASH_REMATCH[1]}
    cmd=${BASH_REMATCH[2]}
  else
    return $_rc
  fi
  # Only a NEW history number is a new command (skips empty Enter / redraws).
  [ "$histno" = "$_LINAUDIT_LAST_HIST" ] && return $_rc
  _LINAUDIT_LAST_HIST=$histno
  [ -z "$cmd" ] && return $_rc
  cmd=${cmd//$'\n'/\\n}
  now=${EPOCHREALTIME:-}                          # bash >=5: seconds.microseconds
  [ -z "$now" ] && printf -v now '%(%s)T' -1      # else integer epoch seconds
  printf -v iso '%(%Y-%m-%dT%H:%M:%S)T' -1
  printf '%s\t%s\ttty=%s\tpid=%s\tEXEC\t%s\n' \
    "$iso" "$now" "$_LINAUDIT_TTY" "$$" "$cmd" 2>/dev/null >> "$_LINAUDIT_CMDLOG"
  return $_rc
}

# Prepend our hook to PROMPT_COMMAND (preserving any existing value), once.
case "${PROMPT_COMMAND:-}" in
  *_linaudit_postcmd*) : ;;
  *) PROMPT_COMMAND="_linaudit_postcmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
