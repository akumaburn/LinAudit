package web

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// TestScryptRFC7914Vectors asserts the two RFC 7914 (section 12) test vectors,
// which is the ground truth that our pure-Go scrypt is byte-compatible with
// Python's hashlib.scrypt and therefore can verify the existing auth.json.
func TestScryptRFC7914Vectors(t *testing.T) {
	cases := []struct {
		name        string
		password    string
		salt        string
		n, r, p, dk int
		want        string
	}{
		{
			name:     "empty-N16-r1-p1",
			password: "",
			salt:     "",
			n:        16, r: 1, p: 1, dk: 64,
			want: "77d6576238657b203b19ca42c18a0497" +
				"f16b4844e3074ae8dfdffa3fede21442" +
				"fcd0069ded0948f8326a753a0fc81f17" +
				"e8d3e0fb2e0d3628cf35e20c38d18906",
		},
		{
			name:     "password-NaCl-N1024-r8-p16",
			password: "password",
			salt:     "NaCl",
			n:        1024, r: 8, p: 16, dk: 64,
			want: "fdbabe1c9d3472007856e7190d01e9fe" +
				"7c6ad7cbc8237830e77376634b373162" +
				"2eaf30d92e22a3886ff109279d9830da" +
				"c727afb94a83ee6d8360cbdfa2cc0640",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dk, err := scryptKey([]byte(c.password), []byte(c.salt), c.n, c.r, c.p, c.dk)
			if err != nil {
				t.Fatalf("scryptKey error: %v", err)
			}
			got := hex.EncodeToString(dk)
			if got != c.want {
				t.Fatalf("scrypt mismatch\n got %s\nwant %s", got, c.want)
			}
		})
	}
}

// TestScryptParamsMatchPython exercises the production parameters (N=1<<15, r=8,
// p=1, dkLen=32) to confirm they produce a 32-byte key without error.
func TestScryptProductionParams(t *testing.T) {
	dk, err := scryptKey([]byte("correct horse battery staple"),
		[]byte("0123456789abcdef"), scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		t.Fatalf("scryptKey error: %v", err)
	}
	if len(dk) != scryptDKLen {
		t.Fatalf("dk length = %d, want %d", len(dk), scryptDKLen)
	}
}

// TestScryptRejectsBadParams checks the validation guards.
func TestScryptRejectsBadParams(t *testing.T) {
	bad := []struct {
		n, r, p, dk int
	}{
		{n: 15, r: 1, p: 1, dk: 32}, // N not a power of two
		{n: 1, r: 1, p: 1, dk: 32},  // N must be > 1
		{n: 16, r: 0, p: 1, dk: 32}, // r must be positive
		{n: 16, r: 1, p: 0, dk: 32}, // p must be positive
		{n: 16, r: 1, p: 1, dk: 0},  // dkLen must be positive
	}
	for _, b := range bad {
		if _, err := scryptKey([]byte("x"), []byte("y"), b.n, b.r, b.p, b.dk); err == nil {
			t.Errorf("scryptKey(%+v) returned nil error, want error", b)
		}
	}
}

// TestSessionLifecycle verifies create/ok/drop and expiry eviction.
func TestSessionLifecycle(t *testing.T) {
	s := newSessionStore()

	tok, err := s.create()
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if tok == "" {
		t.Fatal("create returned empty token")
	}
	if !s.ok(tok) {
		t.Fatal("freshly created session should be ok")
	}
	if s.ok("") {
		t.Fatal("empty token should never be ok")
	}
	if s.ok("nonexistent") {
		t.Fatal("unknown token should not be ok")
	}

	// Expire it in the past and confirm eviction.
	s.mu.Lock()
	s.m[tok] = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if s.ok(tok) {
		t.Fatal("expired session should not be ok")
	}
	s.mu.Lock()
	_, present := s.m[tok]
	s.mu.Unlock()
	if present {
		t.Fatal("expired session should be evicted on access")
	}

	// Drop removes a live session.
	tok2, _ := s.create()
	s.drop(tok2)
	if s.ok(tok2) {
		t.Fatal("dropped session should not be ok")
	}
}

// TestSessionCookieFormat asserts the exact Set-Cookie strings.
func TestSessionCookieFormat(t *testing.T) {
	set := sessionCookie("abc123", false)
	want := "audit_session=abc123; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
	if set != want {
		t.Fatalf("set cookie = %q, want %q", set, want)
	}
	clear := sessionCookie("anything", true)
	wantClear := "audit_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
	if clear != wantClear {
		t.Fatalf("clear cookie = %q, want %q", clear, wantClear)
	}
	if !strings.Contains(set, "HttpOnly") || !strings.Contains(set, "SameSite=Strict") {
		t.Fatal("cookie missing hardening attributes")
	}
}
