// Command linaudit is the single, statically-linked entry point for the LinAudit
// host-monitoring stack. One binary provides every runtime role via subcommands,
// so deployment is a single artifact with no interpreter or shared-library
// dependency (the dashboard markup and world map are embedded with go:embed):
//
//	linaudit web                 dashboard HTTP server on 127.0.0.1:8799
//	linaudit input               evdev input-source attribution logger (root)
//	linaudit store up|down|init  unlock/mount, unmount/close, or create the LUKS store
//	linaudit status              print monitor status
//	linaudit enable  LAYER       LAYER = shell | input | audit | all
//	linaudit disable LAYER
//	linaudit logs    WHICH       WHICH = buffer | exec | keys | devices | usb
//	linaudit report  [N]         correlate the last N prompt entries across planes
//	linaudit live                live unified tail (buffer + commands + keystrokes)
//	linaudit open                open the dashboard in a browser
//	linaudit                     interactive control panel (default)
package main

import (
	"fmt"
	"os"

	"linaudit/cli"
	"linaudit/doctor"
	"linaudit/inputmon"
	"linaudit/storage"
	"linaudit/web"
)

// Version is the LinAudit release. Bump on user-visible changes.
const Version = "2.1.0"

func main() {
	args := os.Args[1:]
	cmd := "menu"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	var err error
	switch cmd {
	case "web":
		err = web.Run()
	case "input":
		err = inputmon.Run()
	case "store":
		err = runStore(args)
	case "status":
		err = cli.Status()
	case "enable":
		err = cli.Enable(arg(args, 0))
	case "disable":
		err = cli.Disable(arg(args, 0))
	case "logs":
		err = cli.Logs(argDefault(args, 0, "buffer"))
	case "report":
		err = cli.Report(argDefault(args, 0, "15"))
	case "live":
		err = cli.Live()
	case "open":
		err = cli.Open()
	case "doctor":
		err = doctor.Run()
	case "menu":
		err = cli.Menu()
	case "version", "-v", "--version":
		fmt.Printf("linaudit %s\n", Version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "linaudit: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "linaudit %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func runStore(args []string) error {
	switch arg(args, 0) {
	case "up":
		return storage.Up()
	case "down":
		return storage.Down()
	case "init":
		return storage.Init()
	default:
		return fmt.Errorf("usage: linaudit store up|down|init")
	}
}

// arg returns args[i] or "".
func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// argDefault returns args[i] or def.
func argDefault(args []string, i int, def string) string {
	if v := arg(args, i); v != "" {
		return v
	}
	return def
}

func usage(w *os.File) {
	fmt.Fprint(w, `linaudit -- local host-monitoring control panel

usage:
  linaudit                      interactive control panel (default)
  linaudit web                  run the dashboard server (127.0.0.1:8799)
  linaudit input                run the input-source attribution logger
  linaudit store up|down|init   unlock/mount, tear down, or create the encrypted store
  linaudit status               print monitor status and exit
  linaudit enable  LAYER        LAYER = shell | input | audit | all
  linaudit disable LAYER
  linaudit logs    WHICH        WHICH = buffer | exec | keys | devices | usb
  linaudit report  [N]          correlate the last N prompt entries
  linaudit live                 live unified tail (buffer + commands + keystrokes)
  linaudit open                 open the dashboard in a browser
  linaudit doctor               check environment readiness on this host
  linaudit version
`)
}
