package snmp

import (
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 3414 appendix A.3, which pin the password-to-key
// expansion and the engine-ID localization step.
func TestPassword2KeyRFC3414(t *testing.T) {
	engineID, err := hex.DecodeString("000000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		proto AuthProto
		kul   string
	}{
		{AuthMD5, "526f5eed9fcce26f8964c2930787d82b"},
		{AuthSHA1, "6695febc9288e36282235fc7151f128497b38f3f"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(Password2Key(c.proto, "maplesyrup", engineID))
		if got != c.kul {
			t.Errorf("%s localized key = %s, want %s", c.proto, got, c.kul)
		}
	}
}

func TestAuthTagLengths(t *testing.T) {
	for proto, want := range map[AuthProto]int{
		AuthMD5: 12, AuthSHA1: 12, AuthSHA256: 24, AuthSHA512: 48,
	} {
		if got := proto.tagLen(); got != want {
			t.Errorf("%s tag length = %d, want %d", proto, got, want)
		}
	}
}

// AES256 needs a 32-byte localized key, which SHA1 cannot produce; the
// non-standard key-extension draft is deliberately not implemented.
func TestDeriveKeysRejectsShortPrivKey(t *testing.T) {
	engineID := []byte("engine-id-12")
	if _, _, err := deriveKeys(AuthSHA1, PrivAES256, "authpassword", "privpassword", engineID); err == nil {
		t.Fatal("expected SHA1 + AES256 to be rejected")
	}
	if _, _, err := deriveKeys(AuthSHA256, PrivAES256, "authpassword", "privpassword", engineID); err != nil {
		t.Fatalf("SHA256 + AES256 should be accepted: %v", err)
	}
}

func TestAESRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	plain := []byte("scoped pdu payload of arbitrary, non-block-aligned length")
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ct, err := encryptAES(key, 7, 1234, salt, plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) == string(plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	back, err := decryptAES(key, 7, 1234, salt, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(plain) {
		t.Fatalf("round trip = %q, want %q", back, plain)
	}
}

func TestParseProtocols(t *testing.T) {
	if a, err := ParseAuthProto("SHA-256"); err != nil || a != AuthSHA256 {
		t.Errorf("ParseAuthProto(SHA-256) = %v, %v", a, err)
	}
	if p, err := ParsePrivProto("aes128"); err != nil || p != PrivAES128 {
		t.Errorf("ParsePrivProto(aes128) = %v, %v", p, err)
	}
	if _, err := ParsePrivProto("DES"); err == nil {
		t.Error("DES should be rejected")
	}
}
