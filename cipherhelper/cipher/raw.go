package cipher

import (
	"fmt"
	"strings"
)

// NewCipherRaw builds a cipher straight from an unpacked DaMod module: the
// template name recorded in the module's .dynstr plus the key/IV the module
// embeds in .data.  The portal hands out the current module on demand, so this
// lets the OpenWrt client follow an algorithm rotation without recompiling
// cipher-helper - only the key material changes.
//
// The template name carries the primitive and the key length carries the
// layering, which is how the module's own metadata block is laid out:
//
//	block size (meta[0]) = 8 for DES, 16 for AES
//	key length (meta[2]) = 48 double-3DES / six-layer DES, 32 double-AES
//	key offset (meta[5]) = start of the key inside .data, IV follows it
func NewCipherRaw(template string, key, iv []byte) (Cipher, error) {
	tpl := strings.ToLower(strings.TrimSpace(template))
	has := func(s string) bool { return strings.Contains(tpl, s) }

	switch {
	case has("aes") && has("cbc"):
		switch len(key) {
		case 32:
			if len(iv) < 16 {
				return nil, fmt.Errorf("aes-cbc: need a 16-byte IV, got %d", len(iv))
			}
			return NewAESDoubleCBCAndroid(key, iv), nil
		case 16:
			if len(iv) < 16 {
				return nil, fmt.Errorf("aes-cbc: need a 16-byte IV, got %d", len(iv))
			}
			return NewAESCBC(key, key, iv), nil
		}
		return nil, fmt.Errorf("aes-cbc: unsupported key length %d", len(key))

	case has("aes") && has("ecb"):
		switch len(key) {
		case 32:
			return NewAESDoubleECBAndroid(key), nil
		case 16:
			return NewAESECB(key, key), nil
		}
		return nil, fmt.Errorf("aes-ecb: unsupported key length %d", len(key))

	case has("des") && has("cbc"), has("des") && has("iv"):
		switch len(key) {
		case 48:
			if len(iv) < 16 {
				return nil, fmt.Errorf("3des-cbc: need a 16-byte IV, got %d", len(iv))
			}
			return NewDESedeDoubleCBCAndroid(key, iv), nil
		case 24:
			if len(iv) < 8 {
				return nil, fmt.Errorf("3des-cbc: need an 8-byte IV, got %d", len(iv))
			}
			return NewDESedeCBC(key, key, iv), nil
		}
		return nil, fmt.Errorf("3des-cbc: unsupported key length %d", len(key))

	case has("des") && has("ecb"):
		switch len(key) {
		case 48:
			return NewDESECBSix(key), nil
		case 16:
			return NewDESedeECB(key, key), nil
		}
		return nil, fmt.Errorf("des-ecb: unsupported key length %d", len(key))

	case has("sm4") && has("cbc"):
		if len(iv) < 16 {
			return nil, fmt.Errorf("sm4-cbc: need a 16-byte IV, got %d", len(iv))
		}
		return NewSM4VariantCBC(key, iv), nil

	case has("sm4") && has("ecb"):
		return NewSM4VariantECB(key), nil

	case has("zuc"):
		if len(iv) < 16 {
			return nil, fmt.Errorf("zuc: need a 16-byte IV, got %d", len(iv))
		}
		return NewZUC(key, iv), nil

	case has("snow3g"):
		if len(iv) < 16 {
			return nil, fmt.Errorf("snow3g: need a 16-byte IV, got %d", len(iv))
		}
		return NewSnow3gVariant(key, iv), nil
	}

	return nil, fmt.Errorf("unsupported module template %q (key=%d iv=%d)", template, len(key), len(iv))
}
