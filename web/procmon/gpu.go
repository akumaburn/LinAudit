package procmon

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nvsmi is the canonical nvidia-smi path; if absent we also accept it on PATH.
const nvsmi = "/usr/bin/nvidia-smi"

// mibRe captures a "<N> MiB" token; the process memory is the LAST such match on
// a Processes-table line (a process name may itself contain "MiB").
var mibRe = regexp.MustCompile(`(\d+)\s*MiB`)

// hasNV reports whether nvidia-smi is available. Mirrors os.path.exists(NVSMI)
// but additionally checks PATH so non-standard installs are still detected.
func hasNV() bool {
	if fi, err := exec.LookPath(nvsmi); err == nil && fi != "" {
		return true
	}
	if _, err := exec.LookPath("nvidia-smi"); err == nil {
		return true
	}
	return false
}

// nvBin returns the nvidia-smi executable to invoke (canonical path if present,
// otherwise the PATH-resolved name).
func nvBin() string {
	if _, err := exec.LookPath(nvsmi); err == nil {
		return nvsmi
	}
	return "nvidia-smi"
}

// run executes args with a timeout and returns stdout; any error yields "".
func run(timeout time.Duration, args ...string) string {
	if len(args) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// numField parses an int defensively via float (int(float(s))); 0 on failure.
func numField(s string) int64 {
	s = strings.TrimSpace(s)
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(v)
	}
	return 0
}

const mib = int64(1) << 20

// gpu returns the aggregate GPU summary (nil when no total) and a pid->VRAM bytes
// map covering BOTH graphics and compute processes, summed across GPUs. Mirrors
// procmon.py _gpu() exactly.
func gpu() (*GPU, map[int]int64) {
	vram := map[int]int64{}
	if !hasNV() {
		return nil, vram
	}
	bin := nvBin()

	// Processes table: after a line containing "Processes:", any line with
	// "MiB" is a process row. Columns (after replacing '|' with space):
	// GPU GI CI PID Type Name... <mem>MiB  -> pid = cols[3].
	seen := false
	for _, ln := range strings.Split(run(3*time.Second, bin), "\n") {
		if strings.Contains(ln, "Processes:") {
			seen = true
			continue
		}
		if !seen || !strings.Contains(ln, "MiB") {
			continue
		}
		cols := strings.Fields(strings.ReplaceAll(ln, "|", " "))
		if len(cols) < 5 {
			continue
		}
		pid, err := strconv.Atoi(cols[3])
		if err != nil {
			continue
		}
		matches := mibRe.FindAllStringSubmatch(ln, -1)
		if len(matches) == 0 {
			continue
		}
		last := matches[len(matches)-1][1]
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil {
			continue
		}
		mem := n * mib
		if mem > vram[pid] {
			vram[pid] = mem
		}
	}

	// Per-GPU summary via --query-gpu, summed across GPUs.
	rows := strings.Split(strings.TrimSpace(run(3*time.Second, bin,
		"--query-gpu=name,memory.used,memory.total,utilization.gpu,utilization.memory",
		"--format=csv,noheader,nounits")), "\n")
	var used, total int64
	var util, ng int
	name := ""
	haveName := false
	for _, r := range rows {
		if strings.TrimSpace(r) == "" {
			continue
		}
		p := strings.Split(r, ",")
		for i := range p {
			p[i] = strings.TrimSpace(p[i])
		}
		if len(p) < 3 {
			continue
		}
		ng++
		if !haveName {
			name = p[0]
			haveName = true
		}
		used += numField(p[1])
		total += numField(p[2])
		if len(p) >= 4 {
			if u := int(numField(p[3])); u > util {
				util = u
			}
		}
	}

	if total <= 0 {
		return nil, vram
	}
	if name == "" {
		name = "GPU"
	}
	if ng > 1 {
		name += " (x" + strconv.Itoa(ng) + ")"
	}
	return &GPU{
		Name:     name,
		MemUsed:  used * mib,
		MemTotal: total * mib,
		Util:     util,
		MemUtil:  0,
	}, vram
}
