package cipher

import "testing"

func TestPublicBuildFailsClosed(t *testing.T) {
	for _, id := range AlgorithmIDs() {
		t.Run(id, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("missing keys must return an error, never panic")
				}
			}()
			if _, err := NewCipher(id); err == nil {
				t.Error("uninitialized key material accepted")
			}
		})
	}
}
func TestRawDES16FailsClosed(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Error("raw DES16 panicked")
		}
	}()
	c, err := NewCipherRaw("tpl_des_ecb.so", []byte("0123456789abcdef"), nil)
	if err == nil {
		_ = c.Encrypt("audit-placeholder")
		t.Error("unverified DES16 protocol must be rejected")
	}
}
func TestRawUnknownTemplateRejected(t *testing.T) {
	if _, err := NewCipherRaw("malicious_aes_ecb_fake.so", []byte("0123456789abcdef"), nil); err == nil {
		t.Fatal("substring template matching accepted unknown protocol")
	}
}
