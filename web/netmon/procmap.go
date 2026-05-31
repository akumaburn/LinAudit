package netmon

import (
	"os"
	"strconv"
	"strings"
)

// procInfo identifies the process owning a socket inode.
type procInfo struct {
	pid  int
	name string
}

// buildInodeMap walks /proc and maps socket inode -> owning (pid, comm) by
// reading each /proc/<pid>/fd/* symlink and matching "socket:[<inode>]". A
// fresh map is built on every sample. Permission errors on individual entries
// are ignored so a partial map is still returned.
func buildInodeMap() map[uint32]procInfo {
	out := map[uint32]procInfo{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue // not a numeric pid dir
		}
		comm := readComm(pid)
		fdDir := "/proc/" + name + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process gone or not permitted
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			ino, ok := parseSocketInode(link)
			if !ok {
				continue
			}
			// First writer wins; a given inode has a single owning fd path, but
			// if several pids share it (rare), keeping the first match is fine.
			if _, exists := out[ino]; !exists {
				out[ino] = procInfo{pid: pid, name: comm}
			}
		}
	}
	return out
}

// parseSocketInode extracts the inode from a "socket:[12345]" symlink target.
func parseSocketInode(link string) (uint32, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	num := link[len(prefix) : len(link)-1]
	v, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// readComm returns the trimmed contents of /proc/<pid>/comm, or "" on error.
func readComm(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n")
}
