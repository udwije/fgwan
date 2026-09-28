package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
)

// AuthProto identifies a USM authentication protocol.
type AuthProto int

// Supported authentication protocols.
const (
	AuthNone AuthProto = iota
	AuthMD5
	AuthSHA1
	AuthSHA256
	AuthSHA512
)

// PrivProto identifies a USM privacy protocol.
type PrivProto int

// Supported privacy protocols.
const (
	PrivNone PrivProto = iota
	PrivAES128
	PrivAES256
)

// ParseAuthProto maps a config string onto an AuthProto.
func ParseAuthProto(s string) (AuthProto, error) {
	switch normalize(s) {
	case "", "none":
		return AuthNone, nil
	case "md5", "hmacmd5":
		return AuthMD5, nil
	case "sha", "sha1", "hmacsha1", "hmacsha":
		return AuthSHA1, nil
	case "sha256", "hmacsha256":
		return AuthSHA256, nil
	case "sha512", "hmacsha512":
		return AuthSHA512, nil
	}
	return AuthNone, fmt.Errorf("snmp: unknown auth protocol %q (want MD5, SHA1, SHA256, SHA512)", s)
}

// ParsePrivProto maps a config string onto a PrivProto.
func ParsePrivProto(s string) (PrivProto, error) {
	switch normalize(s) {
	case "", "none":
		return PrivNone, nil
	case "aes", "aes128", "aescfb128":
		return PrivAES128, nil
	case "aes256", "aescfb256":
		return PrivAES256, nil
	}
	return PrivNone, fmt.Errorf("snmp: unknown priv protocol %q (want AES128 or AES256; DES is not supported)", s)
}

func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}

func (a AuthProto) new() hash.Hash {
	switch a {
	case AuthMD5:
		return md5.New()
	case AuthSHA1:
		return sha1.New()
	case AuthSHA256:
		return sha256.New()
	case AuthSHA512:
		return sha512.New()
	}
	return nil
}

// tagLen is the truncated length of msgAuthenticationParameters (RFC 3414 / RFC 7860).
func (a AuthProto) tagLen() int {
	switch a {
	case AuthMD5, AuthSHA1:
		return 12
	case AuthSHA256:
		return 24
	case AuthSHA512:
		return 48
	}
	return 0
}

func (a AuthProto) String() string {
	switch a {
	case AuthMD5:
		return "MD5"
	case AuthSHA1:
		return "SHA1"
	case AuthSHA256:
		return "SHA256"
	case AuthSHA512:
		return "SHA512"
	}
	return "none"
}

func (p PrivProto) String() string {
	switch p {
	case PrivAES128:
		return "AES128"
	case PrivAES256:
		return "AES256"
	}
	return "none"
}

func (p PrivProto) keyLen() int {
	switch p {
	case PrivAES128:
		return 16
	case PrivAES256:
		return 32
	}
	return 0
}

// Password2Key derives a localized key from a passphrase per RFC 3414 A.2.
// The passphrase is expanded to 1 MiB, hashed, then localized with the engine ID.
func Password2Key(a AuthProto, password string, engineID []byte) []byte {
	h := a.new()
	if h == nil || password == "" {
		return nil
	}
	pw := []byte(password)
	const total = 1048576
	buf := make([]byte, 64)
	idx := 0
	for written := 0; written < total; written += 64 {
		for i := 0; i < 64; i++ {
			buf[i] = pw[idx%len(pw)]
			idx++
		}
		h.Write(buf)
	}
	ku := h.Sum(nil)

	h2 := a.new()
	h2.Write(ku)
	h2.Write(engineID)
	h2.Write(ku)
	return h2.Sum(nil)
}

// deriveKeys produces localized auth and priv keys for a given engine ID.
func deriveKeys(a AuthProto, p PrivProto, authPass, privPass string, engineID []byte) (authKey, privKey []byte, err error) {
	if a == AuthNone {
		return nil, nil, nil
	}
	authKey = Password2Key(a, authPass, engineID)
	if len(authKey) == 0 {
		return nil, nil, fmt.Errorf("snmp: empty auth passphrase")
	}
	if p == PrivNone {
		return authKey, nil, nil
	}
	raw := Password2Key(a, privPass, engineID)
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("snmp: empty priv passphrase")
	}
	need := p.keyLen()
	if len(raw) < need {
		// Extending a short localized key to fit a longer cipher (e.g. SHA1 + AES256)
		// is only defined by a non-standard draft that agents implement inconsistently.
		return nil, nil, fmt.Errorf(
			"snmp: %s yields a %d-byte localized key but %s needs %d; pair AES256 with SHA256 or longer",
			a, len(raw), p, need)
	}
	return authKey, raw[:need], nil
}

// authDigest computes the truncated HMAC over a whole serialized message.
func authDigest(a AuthProto, key, msg []byte) []byte {
	m := hmac.New(a.new, key)
	m.Write(msg)
	return m.Sum(nil)[:a.tagLen()]
}

// aesIV builds the 16-byte CFB IV: engineBoots || engineTime || salt.
func aesIV(boots, etime int32, salt []byte) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(etime))
	copy(iv[8:16], salt)
	return iv
}

// encryptAES encrypts a scoped PDU with AES-CFB128 (RFC 3826).
func encryptAES(key []byte, boots, etime int32, salt, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, aesIV(boots, etime, salt)).XORKeyStream(out, plain)
	return out, nil
}

// decryptAES reverses encryptAES using the salt carried in msgPrivacyParameters.
func decryptAES(key []byte, boots, etime int32, salt, ct []byte) ([]byte, error) {
	if len(salt) != 8 {
		return nil, fmt.Errorf("snmp: bad privacy parameters length %d", len(salt))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCFBDecrypter(block, aesIV(boots, etime, salt)).XORKeyStream(out, ct)
	return out, nil
}
