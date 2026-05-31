package web

import _ "embed"

// Single-binary encapsulation: the dashboard markup and the offline world map are
// compiled into the executable via go:embed, so deployment is one static binary
// with no sidecar files. Both assets live in this directory (web/) because go:embed
// patterns cannot traverse upward ("..").

//go:embed dashboard.html
var DashboardHTML string

//go:embed world.svg
var WorldSVG []byte
