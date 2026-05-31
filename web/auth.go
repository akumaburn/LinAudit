package web

// Authentication for the dashboard: a pure-Go RFC 7914 scrypt implementation
// (byte-compatible with Python hashlib.scrypt so an auth.json written by the
// previous Python stack still verifies), plus the file-backed password record
// and the in-memory session table.
//
// The standard library does not ship scrypt under CGO_ENABLED=0 / no external
// modules, so we implement Salsa20/8, BlockMix, ROMix and the PBKDF2-HMAC-SHA256
// wrapper here. Parameters for new passwords: N=1<<15, r=8, p=1, dkLen=32.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// scrypt parameters used for newly created passwords.
const (
	scryptN     = 1 << 15
	scryptR     = 8
	scryptP     = 1
	scryptDKLen = 32
	scryptSalt  = 16
)

// SESSION_TTL: dashboard sessions live for 12 hours.
const sessionTTLSeconds = 12 * 3600

// authRecord mirrors the on-disk /var/lib/linaudit/auth.json document written by
// the Python stack. salt and hash are base64 (StdEncoding).
type authRecord struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
}

// loadAuth reads and decodes the auth record. Returns nil on any error (missing
// file, bad JSON) -- nil means "not configured yet" exactly like Python.
func loadAuth() *authRecord {
	data, err := os.ReadFile(authFile)
	if err != nil {
		return nil
	}
	var rec authRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil
	}
	return &rec
}

// saveAuth derives a fresh scrypt hash for password and writes the auth record
// 0600. Errors propagate so the caller can report them.
func saveAuth(password string) error {
	salt := make([]byte, scryptSalt)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dk, err := scryptKey([]byte(password), salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return err
	}
	rec := authRecord{
		Salt: base64.StdEncoding.EncodeToString(salt),
		Hash: base64.StdEncoding.EncodeToString(dk),
		N:    scryptN,
		R:    scryptR,
		P:    scryptP,
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(authFile), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(authFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(blob); err != nil {
		return err
	}
	return nil
}

// verifyPw recomputes the scrypt hash with the stored salt/N/r/p and compares in
// constant time against the stored hash. Any error (missing record, bad base64,
// scrypt failure) yields false, matching Python's broad except.
func verifyPw(password string) bool {
	rec := loadAuth()
	if rec == nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(rec.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(rec.Hash)
	if err != nil {
		return false
	}
	dk, err := scryptKey([]byte(password), salt, rec.N, rec.R, rec.P, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// ---------------------------- session table --------------------------------

// sessionStore is the in-memory set of valid session tokens with their expiry.
type sessionStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: map[string]time.Time{}}
}

// create issues a new random session token (32 bytes -> RawURLEncoding) valid
// for 12 hours and records it.
func (s *sessionStore) create() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	s.m[tok] = time.Now().Add(sessionTTLSeconds * time.Second)
	s.mu.Unlock()
	return tok, nil
}

// ok reports whether tok names a live, non-expired session. Expired tokens are
// evicted on access.
func (s *sessionStore) ok(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, present := s.m[tok]
	if !present {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

// drop removes a session token (logout).
func (s *sessionStore) drop(tok string) {
	if tok == "" {
		return
	}
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// sessionCookie builds the exact Set-Cookie value. clear=true logs the session
// out (empty value, Max-Age=0).
func sessionCookie(tok string, clear bool) string {
	if clear {
		return "audit_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
	}
	return "audit_session=" + tok + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
}

// ----------------------------- scrypt core ---------------------------------

// scryptKey is the RFC 7914 scrypt KDF, byte-for-byte compatible with Python's
// hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=dkLen).
func scryptKey(password, salt []byte, n, r, p, dkLen int) ([]byte, error) {
	if n <= 1 || n&(n-1) != 0 {
		return nil, errScrypt("N must be > 1 and a power of two")
	}
	if r <= 0 || p <= 0 {
		return nil, errScrypt("r and p must be positive")
	}
	if dkLen <= 0 {
		return nil, errScrypt("dkLen must be positive")
	}
	// Guard against absurd memory like the reference implementations do; the
	// real ceiling here is well above our N=1<<15,r=8 working set.
	if uint64(r)*uint64(p) >= 1<<30 {
		return nil, errScrypt("parameters too large")
	}

	blockWords := 32 * r // number of uint32 words per scrypt block (128*r bytes)

	// B = PBKDF2(password, salt, 1, p*128*r) reinterpreted as p blocks of uint32.
	b := pbkdf2SHA256(password, salt, 1, p*blockWords*4)
	v := make([]uint32, n*blockWords)
	xy := make([]uint32, 2*blockWords)

	for i := 0; i < p; i++ {
		blk := b[i*blockWords*4 : (i+1)*blockWords*4]
		bytesToUint32LE(blk, xy[:blockWords])
		scryptROMix(xy, v, n, r)
		uint32ToBytesLE(xy[:blockWords], blk)
	}

	return pbkdf2SHA256(password, b, 1, dkLen), nil
}

// scryptROMix runs the RFC 7914 ROMix over the first blockWords words of xy in
// place. v is scratch of n*blockWords words; the second half of xy is scratch.
func scryptROMix(xy, v []uint32, n, r int) {
	blockWords := 32 * r
	x := xy[:blockWords]

	for i := 0; i < n; i++ {
		copy(v[i*blockWords:(i+1)*blockWords], x)
		scryptBlockMix(x, xy[blockWords:], r)
		copy(x, xy[blockWords:blockWords+blockWords])
	}
	for i := 0; i < n; i++ {
		// j = integerify(x) mod N; integerify reads the last 64-byte block's
		// first little-endian uint32. The last block starts at word (2r-1)*16.
		j := int(x[(2*r-1)*16] & uint32(n-1))
		blockXor(x, v[j*blockWords:], blockWords)
		scryptBlockMix(x, xy[blockWords:], r)
		copy(x, xy[blockWords:blockWords+blockWords])
	}
}

// scryptBlockMix implements BlockMix using Salsa20/8. in holds 2r 64-byte blocks
// (32r words); out receives the permuted result (32r words).
func scryptBlockMix(in, out []uint32, r int) {
	var x [16]uint32
	copy(x[:], in[(2*r-1)*16:(2*r-1)*16+16])

	var tmp [16]uint32
	for i := 0; i < 2*r; i++ {
		for k := 0; k < 16; k++ {
			x[k] ^= in[i*16+k]
		}
		salsa20Core8(&tmp, &x)
		x = tmp
		// Even i -> first half of out, odd i -> second half (RFC 7914 ordering).
		if i%2 == 0 {
			copy(out[(i/2)*16:], x[:])
		} else {
			copy(out[(i/2+r)*16:], x[:])
		}
	}
}

// salsa20Core8 computes the Salsa20/8 core: out = in + rounds(in), 8 rounds.
func salsa20Core8(out, in *[16]uint32) {
	var x [16]uint32
	x = *in
	for i := 0; i < 8; i += 2 {
		// Column round.
		x[4] ^= rotl(x[0]+x[12], 7)
		x[8] ^= rotl(x[4]+x[0], 9)
		x[12] ^= rotl(x[8]+x[4], 13)
		x[0] ^= rotl(x[12]+x[8], 18)

		x[9] ^= rotl(x[5]+x[1], 7)
		x[13] ^= rotl(x[9]+x[5], 9)
		x[1] ^= rotl(x[13]+x[9], 13)
		x[5] ^= rotl(x[1]+x[13], 18)

		x[14] ^= rotl(x[10]+x[6], 7)
		x[2] ^= rotl(x[14]+x[10], 9)
		x[6] ^= rotl(x[2]+x[14], 13)
		x[10] ^= rotl(x[6]+x[2], 18)

		x[3] ^= rotl(x[15]+x[11], 7)
		x[7] ^= rotl(x[3]+x[15], 9)
		x[11] ^= rotl(x[7]+x[3], 13)
		x[15] ^= rotl(x[11]+x[7], 18)

		// Row round.
		x[1] ^= rotl(x[0]+x[3], 7)
		x[2] ^= rotl(x[1]+x[0], 9)
		x[3] ^= rotl(x[2]+x[1], 13)
		x[0] ^= rotl(x[3]+x[2], 18)

		x[6] ^= rotl(x[5]+x[4], 7)
		x[7] ^= rotl(x[6]+x[5], 9)
		x[4] ^= rotl(x[7]+x[6], 13)
		x[5] ^= rotl(x[4]+x[7], 18)

		x[11] ^= rotl(x[10]+x[9], 7)
		x[8] ^= rotl(x[11]+x[10], 9)
		x[9] ^= rotl(x[8]+x[11], 13)
		x[10] ^= rotl(x[9]+x[8], 18)

		x[12] ^= rotl(x[15]+x[14], 7)
		x[13] ^= rotl(x[12]+x[15], 9)
		x[14] ^= rotl(x[13]+x[12], 13)
		x[15] ^= rotl(x[14]+x[13], 18)
	}
	for i := 0; i < 16; i++ {
		out[i] = x[i] + in[i]
	}
}

func rotl(v uint32, n uint) uint32 { return (v << n) | (v >> (32 - n)) }

// blockXor XORs src into dst for the first count words.
func blockXor(dst, src []uint32, count int) {
	for i := 0; i < count; i++ {
		dst[i] ^= src[i]
	}
}

func bytesToUint32LE(src []byte, dst []uint32) {
	for i := range dst {
		dst[i] = binary.LittleEndian.Uint32(src[i*4:])
	}
}

func uint32ToBytesLE(src []uint32, dst []byte) {
	for i, v := range src {
		binary.LittleEndian.PutUint32(dst[i*4:], v)
	}
}

// pbkdf2SHA256 is PBKDF2 with HMAC-SHA256 as the PRF (RFC 8018), enough for the
// scrypt wrapper. Returns keyLen bytes.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen

	dk := make([]byte, 0, numBlocks*hLen)
	var blockIdx [4]byte
	u := make([]byte, hLen)
	t := make([]byte, hLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockIdx[:], uint32(block))
		prf.Write(blockIdx[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

type scryptError string

func (e scryptError) Error() string { return "scrypt: " + string(e) }

func errScrypt(msg string) error { return scryptError(msg) }
