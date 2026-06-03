package web

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShellHookWired checks that the shell-plane detector recognizes the hook
// wired via any supported shell, and is not fooled by unrelated rc content.
func TestShellHookWired(t *testing.T) {
	write := func(dir, rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("none", func(t *testing.T) {
		if shellHookWired(t.TempDir()) {
			t.Errorf("empty home reported wired")
		}
	})
	t.Run("zsh", func(t *testing.T) {
		d := t.TempDir()
		write(d, ".zshrc", "# LinAudit\nsource ~/.config/zsh/linaudit.zsh\n")
		if !shellHookWired(d) {
			t.Errorf("zshrc with hook not detected")
		}
	})
	t.Run("bash", func(t *testing.T) {
		d := t.TempDir()
		write(d, ".bashrc", "# LinAudit\n. ~/.config/bash/linaudit.bash\n")
		if !shellHookWired(d) {
			t.Errorf("bashrc with hook not detected")
		}
	})
	t.Run("fish", func(t *testing.T) {
		d := t.TempDir()
		write(d, ".config/fish/conf.d/linaudit.fish", "# LinAudit fish hook\n")
		if !shellHookWired(d) {
			t.Errorf("fish conf.d drop-in not detected")
		}
	})
	t.Run("unrelated", func(t *testing.T) {
		d := t.TempDir()
		write(d, ".bashrc", "alias ll='ls -l'\nexport PATH=$PATH:/opt/bin\n")
		write(d, ".zshrc", "autoload -Uz compinit\n")
		if shellHookWired(d) {
			t.Errorf("unrelated rc content reported wired")
		}
	})
}
