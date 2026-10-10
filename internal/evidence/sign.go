package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Signer signs bundles with an Ed25519 private key (PKCS#8 PEM, the format
// `openssl genpkey -algorithm ed25519` also produces).
type Signer struct {
	key ed25519.PrivateKey
}

func (s *Signer) Sign(data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, data))
}

// GenerateKeyPair writes <prefix>.key (private, 0600) and <prefix>.pub.
// Existing files are never overwritten: losing a signing key silently
// would orphan every bundle signed with it.
func GenerateKeyPair(prefix string) (pubPath, keyPath string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	keyPath, pubPath = prefix+".key", prefix+".pub"
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		return "", "", err
	}
	if err := writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		return "", "", err
	}
	return pubPath, keyPath, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func LoadSigner(path string) (*Signer, error) {
	block, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return &Signer{key: priv}, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	block, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 public key", path)
	}
	return pub, nil
}

func readPEM(path, wantType string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != wantType {
		return nil, fmt.Errorf("%s: expected a PEM %q block", path, wantType)
	}
	return block, nil
}

// Fingerprint identifies a public key in reports (first 16 hex of SHA-256).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

var ErrBadSignature = errors.New("signature does not match: the evidence was modified or signed with another key")

// Verify checks data against a base64 signature (the content of a .sig file).
func Verify(pub ed25519.PublicKey, data []byte, sigText string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigText))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed signature")
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}

// VerifyDigest checks data against a sha256sum-format line (.sha256 file).
func VerifyDigest(data []byte, digestText string) error {
	fields := strings.Fields(digestText)
	if len(fields) == 0 {
		return fmt.Errorf("empty digest file")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(fields[0], hex.EncodeToString(sum[:])) {
		return fmt.Errorf("SHA-256 mismatch: the evidence was modified")
	}
	return nil
}
