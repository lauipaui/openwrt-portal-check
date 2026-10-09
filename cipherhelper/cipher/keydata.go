package cipher

// Key data for all cipher algorithm IDs.

// -----------------------------------------------------------------
// 旧版 Android 算法 (Android old - 已弃用但保持向下兼容)
// -----------------------------------------------------------------

// CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E (AES-CBC)
var (
	KeyCAFBCBAD_Key1 []byte
	KeyCAFBCBAD_Key2 []byte
	KeyCAFBCBAD_IV []byte
)

// A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4 (AES-ECB)
var (
	KeyA474B1C2_Key1 []byte
	KeyA474B1C2_Key2 []byte
)

// 5BFBA864-BBA9-42DB-8EAD-49B5F412BD81 (DESede-CBC)
var (
	Key5BFBA864_Key1 []byte
	Key5BFBA864_Key2 []byte
	Key5BFBA864_IV []byte
)

// 6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5 (DESede-ECB)
var (
	Key6E0B65FF_Key1 []byte
	Key6E0B65FF_Key2 []byte
)

// B809531F-0007-4B5B-923B-4BD560398113 (ZUC)
var (
	KeyB809531F_Key []byte
	KeyB809531F_IV []byte
)

// F3974434-C0DD-4C20-9E87-DDB6814A1C48 (SM4-CBC)
var (
	KeyF3974434_Key []byte
	KeyF3974434_IV []byte
)

// ED382482-F72C-4C41-A76D-28EEA0F1F2AF (SM4-ECB)
var (
	KeyED382482_Key []byte
)

// B3047D4E-67DF-4864-A6A5-DF9B9E525C79 (ModXTEA)
var (
	KeyB3047D4E_Key1 [4]uint32
	KeyB3047D4E_Key2 [4]uint32
	KeyB3047D4E_Key3 [4]uint32
)

// C32C68F9-CA81-4260-A329-BBAFD1A9CCD1 (ModXTEA with XTEA IV)
var (
	KeyC32C68F9_Key1 [4]uint32
	KeyC32C68F9_Key2 [4]uint32
	KeyC32C68F9_Key3 [4]uint32
	KeyC32C68F9_IV [2]uint32
)

// -----------------------------------------------------------------
// Linux 平台算法 (Linux)
// -----------------------------------------------------------------

// 1A7343EC-7F9B-4570-BF58-16279A81116B (DESede/CBC/Two-Layer)
var (
	Key1A7343EC_Key1 []byte
	Key1A7343EC_Key2 []byte
	Key1A7343EC_IV1 []byte
	Key1A7343EC_IV2 []byte
)

// 4BA5496A-2123-46A7-85F2-35956EA7BE39 (AES/ECB/Two-Layer)
var (
	Key4BA5496A_Key1 []byte
	Key4BA5496A_Key2 []byte
)

// 45433DCF-9ECA-4BE5-83F2-F92BA0B4F291 (AES/CBC/Two-Layer)
var (
	Key45433DCF_Key1 []byte
	Key45433DCF_Key2 []byte
)

// 60639D8B-272E-4A4D-976E-AA270987A169 (XTEA Triple-Layer)
var (
	Key60639D8B_Key1 [4]uint32
	Key60639D8B_Key2 [4]uint32
	Key60639D8B_Key3 [4]uint32
)

// AB6C8EBE-B8F8-4C08-8222-69A3B5E86A91 (AB6C8 TEA CBC Triple)
var (
	KeyAB6C8EBE_Key1 [4]uint32
	KeyAB6C8EBE_Key2 [4]uint32
	KeyAB6C8EBE_Key3 [4]uint32
	KeyAB6C8EBE_IV [2]uint32
)

// B306E770-B7D5-49F2-A574-BCE2C5C650ED (DES 6-stage)
var (
	KeyB306E770_Key1 []byte
	KeyB306E770_Key2 []byte
	KeyB306E770_Key3 []byte
	KeyB306E770_Key4 []byte
	KeyB306E770_Key5 []byte
	KeyB306E770_Key6 []byte
)

// -----------------------------------------------------------------
// 最新 Android 算法 (Android new)
// -----------------------------------------------------------------

// 07E824B2-9E5C-4D1B-BBB0-5E07C251E4AA (SNOW3G-variant)
var (
	Key07E824B2_Key []byte
	Key07E824B2_IV []byte
)

// 319FC5AB-EC0E-46B9-A252-2285F9DAE813 (Triple modified-TEA ECB)
var (
	Key319FC5AB_Key []byte
)

// D6544CFE-F2DE-459B-9B77-0F2B367EF169 (SM4-variant CBC)
var (
	KeyD6544CFE_Key []byte
	KeyD6544CFE_IV []byte
)

// D755A536-B551-468C-BD87-322182B223D4 (SM4-variant ECB)
var (
	KeyD755A536_Key []byte
	KeyD755A536_IV []byte
)

// BB2EA626-590B-4C42-82BE-E052FCBBB88E (double AES-128-CBC)
var (
	KeyBB2EA626_Key []byte
	KeyBB2EA626_IV []byte
)

// DEABB8C8-A2BC-48CA-8ED0-8CDF1BD62F61 (double AES-128-ECB)
var (
	KeyDEABB8C8_Key []byte
	KeyDEABB8C8_IV []byte
)

// 9ABF4D29-34DB-4CE9-BB8C-7E371D637758 (double 3DES-CBC)
var (
	Key9ABF4D29_Key []byte
	Key9ABF4D29_IV []byte
)

// AD8BB5B0-0E72-4198-A362-96D52C1B7ED1 (six-layer DES-ECB)
var (
	KeyAD8BB5B0_Key []byte
	KeyAD8BB5B0_IV []byte
)

// 35101415-A20F-4DFE-B00B-0B4F3B2F8C66 (triple modified-TEA CBC)
var (
	Key35101415_Key []byte
	Key35101415_IV []byte
)
