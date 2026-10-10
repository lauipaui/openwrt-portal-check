package cipher

import (
	"bytes"
	"testing"
)

func TestLocalInitAssignmentsRemainCompatible(t *testing.T) {
	oldK, oldIV := Key9ABF4D29_Key, Key9ABF4D29_IV
	defer func() { Key9ABF4D29_Key, Key9ABF4D29_IV = oldK, oldIV }()
	Key9ABF4D29_Key = make([]byte, 48)
	for i := range Key9ABF4D29_Key {
		Key9ABF4D29_Key[i] = byte(i + 1)
	}
	Key9ABF4D29_IV = make([]byte, 16)
	for i := range Key9ABF4D29_IV {
		Key9ABF4D29_IV[i] = byte(i + 1)
	}
	c, e := NewCipher("9ABF4D29-34DB-4CE9-BB8C-7E371D637758")
	if e != nil {
		t.Fatal(e)
	}
	s := c.Encrypt("audit-placeholder")
	if s == "" || c.Decrypt(s) != "audit-placeholder" {
		t.Fatal("init-style loaded key rejected")
	}
	for _, bad := range []string{"00", "not-hex", string(bytes.Repeat([]byte{'A'}, 18))} {
		if c.Decrypt(bad) != "" {
			t.Fatal("invalid ciphertext accepted")
		}
	}
	Key9ABF4D29_Key = make([]byte, 48)
	if _, e = NewCipher("9ABF4D29-34DB-4CE9-BB8C-7E371D637758"); e == nil {
		t.Fatal("explicit zero key accepted")
	}
}
