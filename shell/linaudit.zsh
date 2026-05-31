# LinAudit: capture executed commands AND any text that appears in the line
# editor (even if it is never executed). Logs are local and 0600. Toggle live via
# the "disabled" flag file (managed by `linaudit`). Coexists with the manjaro
# zsh autosuggestions/syntax-highlighting because it uses add-zle-hook-widget.

zmodload -i zsh/datetime 2>/dev/null
autoload -Uz add-zsh-hook add-zle-hook-widget

typeset -g _AUDIT_DIR="${HOME}/.local/share/linaudit"
typeset -g _AUDIT_CMDLOG="${_AUDIT_DIR}/commands.log"
typeset -g _AUDIT_BUFLOG="${_AUDIT_DIR}/buffer.log"
typeset -g _audit_last_buffer=""

[[ -d "$_AUDIT_DIR" ]] || { mkdir -p "$_AUDIT_DIR" && chmod 700 "$_AUDIT_DIR"; }
[[ -e "$_AUDIT_CMDLOG" ]] || { : >> "$_AUDIT_CMDLOG" 2>/dev/null && chmod 600 "$_AUDIT_CMDLOG"; }
[[ -e "$_AUDIT_BUFLOG" ]] || { : >> "$_AUDIT_BUFLOG" 2>/dev/null && chmod 600 "$_AUDIT_BUFLOG"; }

_audit_enabled() { [[ ! -e "${_AUDIT_DIR}/disabled" ]] }
_audit_ts()      { strftime '%Y-%m-%dT%H:%M:%S' $EPOCHSECONDS }

# Fires before each command is executed.
_audit_preexec() {
  _audit_enabled || return
  print -r -- "$(_audit_ts)	${EPOCHREALTIME}	tty=${TTY}	pid=$$	EXEC	${1}" 2>/dev/null >> "$_AUDIT_CMDLOG"
}

# Fires on every line-editor redraw. Deduped on buffer content, so a command that
# is *typed* grows one character per entry, while a command that is *pasted or
# injected* appears in a single entry as the whole string -> the key discriminator.
_audit_zle_buffer() {
  _audit_enabled || return
  [[ "$BUFFER" == "$_audit_last_buffer" ]] && return
  _audit_last_buffer="$BUFFER"
  [[ -z "$BUFFER" ]] && return
  print -r -- "$(_audit_ts)	${EPOCHREALTIME}	tty=${TTY}	pid=$$	BUFFER	${BUFFER//$'\n'/\\n}" 2>/dev/null >> "$_AUDIT_BUFLOG"
}

add-zsh-hook preexec _audit_preexec
add-zle-hook-widget line-pre-redraw _audit_zle_buffer
