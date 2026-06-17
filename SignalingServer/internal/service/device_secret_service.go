package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// DeviceSecretService encapsulates generation, hashing and verification of
// device_secret strings. The plaintext secret is ONLY returned to the host
// once, at provision (or rotate); subsequent verifications use the argon2id
// hash persisted in `devices.device_secret_hash`.
//
// Hash format is self-describing so we can tune parameters later without a
// migration:
//
//	argon2id$v=19$t=<time>$m=<memoryKB>$p=<parallelism>$<saltB64>$<hashB64>
type DeviceSecretService struct {
	time      uint32
	memoryKB  uint32
	threads   uint8
	keyLen    uint32
	saltLen   uint32
	secretLen int
	verifySem chan struct{}
	cacheMu   sync.Mutex
	cache     map[string]time.Time
}

// NewDeviceSecretService returns a service preconfigured for frequent device
// API authentication. Device secrets are high-entropy random values, so this
// does not need password-grade Argon2 cost on every heartbeat.
func NewDeviceSecretService() *DeviceSecretService {
	return &DeviceSecretService{
		time:      1,
		memoryKB:  8 * 1024,
		threads:   1,
		keyLen:    32,
		saltLen:   16,
		secretLen: 48, // 48 bytes hex ≈ 96 chars, plenty of entropy
		verifySem: make(chan struct{}, 2),
		cache:     map[string]time.Time{},
	}
}

// Generate returns a new random plaintext device_secret as hex.
func (s *DeviceSecretService) Generate() (string, error) {
	buf := make([]byte, s.secretLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Hash returns the canonical storage string for the given plaintext.
func (s *DeviceSecretService) Hash(secret string) (string, error) {
	salt := make([]byte, s.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gen salt: %w", err)
	}
	digest := argon2.IDKey([]byte(secret), salt, s.time, s.memoryKB, s.threads, s.keyLen)

	return fmt.Sprintf(
		"argon2id$v=%d$t=%d$m=%d$p=%d$%s$%s",
		argon2.Version,
		s.time, s.memoryKB, s.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// Verify checks a plaintext secret against a stored hash. Uses
// constant-time comparison.
func (s *DeviceSecretService) Verify(secret, stored string) (bool, error) {
	cacheKey := s.cacheKey(secret, stored)
	if s.cacheHit(cacheKey) {
		return true, nil
	}
	s.verifySem <- struct{}{}
	defer func() { <-s.verifySem }()
	if s.cacheHit(cacheKey) {
		return true, nil
	}

	parts := strings.Split(stored, "$")
	if len(parts) != 7 || parts[0] != "argon2id" {
		return false, errors.New("unknown hash format")
	}
	if !strings.HasPrefix(parts[1], "v=") {
		return false, errors.New("hash missing version")
	}
	tVal, err := parseParam(parts[2], "t=")
	if err != nil {
		return false, err
	}
	mVal, err := parseParam(parts[3], "m=")
	if err != nil {
		return false, err
	}
	pVal, err := parseParam(parts[4], "p=")
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[6])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	got := argon2.IDKey([]byte(secret), salt,
		uint32(tVal), uint32(mVal), uint8(pVal), uint32(len(want)))

	ok := subtle.ConstantTimeCompare(got, want) == 1
	if ok {
		s.cacheStore(cacheKey)
	}
	return ok, nil
}

func (s *DeviceSecretService) cacheKey(secret, stored string) string {
	sum := sha256.Sum256([]byte(secret + "\x00" + stored))
	return hex.EncodeToString(sum[:])
}

func (s *DeviceSecretService) cacheHit(key string) bool {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	expires, ok := s.cache[key]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(s.cache, key)
		return false
	}
	return true
}

func (s *DeviceSecretService) cacheStore(key string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if len(s.cache) > 4096 {
		now := time.Now()
		for k, expires := range s.cache {
			if now.After(expires) {
				delete(s.cache, k)
			}
		}
	}
	s.cache[key] = time.Now().Add(10 * time.Minute)
}

func parseParam(part, prefix string) (uint64, error) {
	if !strings.HasPrefix(part, prefix) {
		return 0, fmt.Errorf("expected %q, got %q", prefix, part)
	}
	return strconv.ParseUint(strings.TrimPrefix(part, prefix), 10, 32)
}
