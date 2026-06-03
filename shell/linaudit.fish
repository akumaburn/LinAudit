# LinAudit: capture executed commands in fish into the shared command log, in the
# exact tab-separated format the dashboard and CLI parse. Logs are local and 0600.
# Toggle live via the shared "disabled" flag file (managed by `linaudit`).
#
# Drop this file in ~/.config/fish/conf.d/ -- fish auto-sources it for interactive
# sessions (no config.fish edit needed). Requires fish >= 3.0 ($fish_pid).
#
# Scope note: fish has no per-keystroke line-editor hook, so this captures only
# EXECUTED commands via the fish_preexec event -- the unexecuted prompt-text plane
# (buffer.log) is zsh-only. The input-device plane (linaudit-input) still records
# the per-keystroke source for ALL shells, which is what lets you tell typed from
# pasted/injected when correlating against EXEC.

if status is-interactive
    set -g _linaudit_dir "$HOME/.local/share/linaudit"
    set -g _linaudit_cmdlog "$_linaudit_dir/commands.log"
    set -g _linaudit_tty (tty 2>/dev/null; or echo '?')

    test -d "$_linaudit_dir"; or begin
        mkdir -p "$_linaudit_dir"; and chmod 700 "$_linaudit_dir"
    end
    test -e "$_linaudit_cmdlog"; or begin
        touch "$_linaudit_cmdlog" 2>/dev/null; and chmod 600 "$_linaudit_cmdlog"
    end

    # Fires immediately before each interactive command runs ($argv[1] is the full
    # command line). True preexec timing, mirroring zsh's preexec.
    function _linaudit_preexec --on-event fish_preexec
        test -e "$_linaudit_dir/disabled"; and return
        set -l cmd (string replace -a \n '\n' -- $argv[1])
        test -z "$cmd"; and return
        set -l iso (date '+%Y-%m-%dT%H:%M:%S')
        set -l epoch (date '+%s.%N')
        printf '%s\t%s\ttty=%s\tpid=%s\tEXEC\t%s\n' \
            $iso $epoch $_linaudit_tty $fish_pid $cmd 2>/dev/null >>"$_linaudit_cmdlog"
    end
end
