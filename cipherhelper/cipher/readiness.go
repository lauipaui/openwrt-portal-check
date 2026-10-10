package cipher

import (
	"fmt"
	"strings"
)

// Readiness is derived after local init assignments, preserving keydata_local.go.
// Default fixed arrays are not evidence of loaded keys. All-zero keys fail closed.
func keyReady(id string) error {
	switch strings.ToUpper(id) {
	case "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E":
		if !bytesReady(KeyCAFBCBAD_Key1, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyCAFBCBAD_Key2, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyCAFBCBAD_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4":
		if !bytesReady(KeyA474B1C2_Key1, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyA474B1C2_Key2, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81":
		if !bytesReady(Key5BFBA864_Key1, true, 24) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key5BFBA864_Key2, true, 24) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key5BFBA864_IV, false, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5":
		if !bytesReady(Key6E0B65FF_Key1, true, 24) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key6E0B65FF_Key2, true, 24) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "B809531F-0007-4B5B-923B-4BD560398113":
		if !bytesReady(KeyB809531F_Key, true, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyB809531F_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "F3974434-C0DD-4C20-9E87-DDB6814A1C48":
		if !bytesReady(KeyF3974434_Key, true, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyF3974434_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "ED382482-F72C-4C41-A76D-28EEA0F1F2AF":
		if !bytesReady(KeyED382482_Key, true, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "B3047D4E-67DF-4864-A6A5-DF9B9E525C79":
		if !wordsReady(KeyB3047D4E_Key1[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyB3047D4E_Key2[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyB3047D4E_Key3[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1":
		if !wordsReady(KeyC32C68F9_Key1[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyC32C68F9_Key2[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyC32C68F9_Key3[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyC32C68F9_IV[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA":
		if !bytesReady(Key07E824B2_Key, true, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key07E824B2_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "319FC5AB-EC0E-46B9-A252-2285F9DAE813":
		if !bytesReady(Key319FC5AB_Key, true, 48) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "D6544CFE-F2DE-459B-9B77-0F2B367EF169":
		if !bytesReady(KeyD6544CFE_Key, true, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyD6544CFE_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "D755A536-B551-468C-BD87-322182B223D4":
		if !bytesReady(KeyD755A536_Key, true, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "BB2EA626-590B-4C42-82BE-E052FCBBB88E":
		if !bytesReady(KeyBB2EA626_Key, true, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyBB2EA626_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61":
		if !bytesReady(KeyDEABB8C8_Key, true, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "9ABF4D29-34DB-4CE9-BB8C-7E371D637758":
		if !bytesReady(Key9ABF4D29_Key, true, 48) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key9ABF4D29_IV, false, 16) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "AD8BB5B0-0E72-4198-A362-96D52C1B7ED1":
		if !bytesReady(KeyAD8BB5B0_Key, true, 48) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "35101415-A20F-4DFE-B00B-0B4F3B2F8C66":
		if !bytesReady(Key35101415_Key, true, 48) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key35101415_IV, false, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "1A7343EC-7F9B-4570-BF58-16279A81116B":
		if !bytesReady(Key1A7343EC_Key1, true, 24) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key1A7343EC_Key2, true, 24) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key1A7343EC_IV1, false, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key1A7343EC_IV2, false, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "4BA5496A-2123-46A7-85F2-35956EA7BE39":
		if !bytesReady(Key4BA5496A_Key1, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key4BA5496A_Key2, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "45433DCF-9ECA-4BE5-83F2-F92BA0B4F291":
		if !bytesReady(Key45433DCF_Key1, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(Key45433DCF_Key2, true, 16, 24, 32) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "60639D8B-272E-4A4D-976E-AA270987A169":
		if !wordsReady(Key60639D8B_Key1[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(Key60639D8B_Key2[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(Key60639D8B_Key3[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91":
		if !wordsReady(KeyAB6C8EBE_Key1[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyAB6C8EBE_Key2[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyAB6C8EBE_Key3[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !wordsReady(KeyAB6C8EBE_IV[:]) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	case "B306E770-B7D5-49F2-A574-BCE2C5C650ED":
		if !bytesReady(KeyB306E770_Key1, true, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyB306E770_Key2, true, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyB306E770_Key3, true, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyB306E770_Key4, true, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyB306E770_Key5, true, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
		if !bytesReady(KeyB306E770_Key6, true, 8) {
			return fmt.Errorf("key material unavailable for %s", id)
		}
	default:
		return fmt.Errorf("unknown algorithm: %s", id)
	}
	return nil
}
func bytesReady(b []byte, key bool, lens ...int) bool {
	ok := false
	for _, n := range lens {
		if len(b) == n {
			ok = true
		}
	}
	if !ok {
		return false
	}
	if !key {
		return true
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func wordsReady(b []uint32) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
