package cipher

import (
	"fmt"
	"strings"
)

// Templates are protocol identifiers, never substring guesses. DES16 is rejected:
// no verified protocol vector establishes two-key 3DES semantics for that module.
func NewCipherRaw(template string, key, iv []byte) (c Cipher, err error) {
	defer func() {
		if recover() != nil {
			c = nil
			err = fmt.Errorf("invalid raw cipher parameters")
		}
	}()
	k := func(n ...int) bool { return bytesReady(key, true, n...) }
	v := func(n int) bool { return len(iv) == n }
	switch strings.ToLower(template) {
	case "tpl_aes_cbc.so":
		if !v(16) {
			break
		}
		if k(32) {
			c = NewAESDoubleCBCAndroid(key, iv)
		} else if k(16) {
			c = NewAESCBC(key, key, iv)
		}
	case "tpl_aes_ecb.so":
		if k(32) {
			c = NewAESDoubleECBAndroid(key)
		} else if k(16) {
			c = NewAESECB(key, key)
		}
	case "tpl_des_iv.so", "tpl_des_cbc.so":
		if k(48) && v(16) {
			c = NewDESedeDoubleCBCAndroid(key, iv)
		} else if k(24) && v(8) {
			c = NewDESedeCBC(key, key, iv)
		}
	case "tpl_des.so", "tpl_des_ecb.so":
		if k(48) {
			c = NewDESECBSix(key)
		} else if k(24) {
			c = NewDESedeECB(key, key)
		}
	case "tpl_sm4_cbc.so":
		if k(16) && v(16) {
			c = NewSM4VariantCBC(key, iv)
		}
	case "tpl_sm4_ecb.so":
		if k(16) {
			c = NewSM4VariantECB(key)
		}
	case "tpl_zuc.so":
		if k(16) && v(16) {
			c = NewZUC(key, iv)
		}
	case "tpl_snow3g.so":
		if k(16) && v(16) {
			c = NewSnow3gVariant(key, iv)
		}
	default:
		return nil, fmt.Errorf("unsupported module template")
	}
	if c == nil {
		return nil, fmt.Errorf("invalid or unavailable key/IV for template %s", template)
	}
	return guarded{c}, nil
}
