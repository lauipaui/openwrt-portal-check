// cipher-helper exposes the CNDATA/DaMod cipher set as a tiny CLI so the
// OpenWrt shell client can offload algorithms the router's OpenSSL cannot do
// (SM4, ZUC, SNOW3G and the XTEA variants).
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"cipherhelper/cipher"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cipher-helper <encrypt|decrypt|check|list> [algo-id]")
	fmt.Fprintln(os.Stderr, "  encrypt <algo-id>  read plaintext on stdin, write uppercase hex to stdout")
	fmt.Fprintln(os.Stderr, "  decrypt <algo-id>  read hex on stdin, write plaintext to stdout")
	fmt.Fprintln(os.Stderr, "  check   <algo-id>  exit 0 only when the algorithm and loaded key material are ready")
	fmt.Fprintln(os.Stderr, "  list               print every supported algorithm ID")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  encrypt-raw <template> <keyhex> [ivhex]   (same as encrypt, key material from a DaMod module)")
	fmt.Fprintln(os.Stderr, "  decrypt-raw <template> <keyhex> [ivhex]   (same as decrypt, key material from a DaMod module)")
	fmt.Fprintln(os.Stderr, "  client <config> <ticket|auth|keep|self-test>  safe protocol client")
	fmt.Fprintln(os.Stderr, "  probe <url> <timeout-seconds>              strict no-redirect HTTP 204")
	fmt.Fprintln(os.Stderr, "  config-get|config-set|config-normalize|candidate-prepare|candidate-activate (see docs/SECURITY-2026-10-10.md)")
	os.Exit(2)
}

// stripSpace removes every whitespace byte so hex may be piped in with line
// breaks or a trailing newline.
func stripSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func readStdin() string {
	data, err := readLimited(os.Stdin, responseLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher-helper: cannot read stdin: %v\n", err)
		os.Exit(1)
	}
	return string(data)
}

// runCipher applies impl to stdin, keeping the output conventions the shell
// client relies on: encrypt emits bare uppercase hex (it is MD5ed verbatim),
// decrypt emits raw plaintext.
func runCipher(encrypt bool, impl cipher.Cipher) {
	if encrypt {
		out := impl.Encrypt(readStdin())
		if out == "" {
			fmt.Fprintln(os.Stderr, "cipher-helper: encryption produced no output")
			os.Exit(1)
		}
		fmt.Print(out)
		return
	}
	in := stripSpace(readStdin())
	out := impl.Decrypt(in)
	if out == "" {
		fmt.Fprintln(os.Stderr, "cipher-helper: decryption produced no output")
		os.Exit(1)
	}
	os.Stdout.WriteString(out)
}

// runRaw handles the *-raw modes.  The template name and key/IV come from an
// unpacked DaMod module (see the damod tool), which is what the portal serves
// whenever it rotates the algorithm.
func runRaw(encrypt bool) {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: cipher-helper encrypt-raw|decrypt-raw <template> <keyhex> [ivhex]")
		os.Exit(2)
	}
	key, err := hex.DecodeString(stripSpace(os.Args[3]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher-helper: bad key hex: %v\n", err)
		os.Exit(2)
	}
	var iv []byte
	if len(os.Args) > 4 {
		iv, err = hex.DecodeString(stripSpace(os.Args[4]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cipher-helper: bad iv hex: %v\n", err)
			os.Exit(2)
		}
	}
	impl, err := cipher.NewCipherRaw(os.Args[2], key, iv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher-helper: %v\n", err)
		os.Exit(3)
	}
	runCipher(encrypt, impl)
}

func main() {
	if handled, err := portalCommand(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "cipher-helper: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		usage()
	}
	mode := strings.ToLower(os.Args[1])

	if mode == "list" {
		for _, id := range cipher.AlgorithmIDs() {
			fmt.Println(id)
		}
		return
	}
	if mode == "encrypt-raw" || mode == "decrypt-raw" {
		runRaw(mode == "encrypt-raw")
		return
	}
	if len(os.Args) < 3 {
		usage()
	}

	algoID := os.Args[2]
	impl, err := cipher.NewCipher(algoID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher-helper: %v\n", err)
		os.Exit(3)
	}

	switch mode {
	case "check":
		return
	case "encrypt":
		runCipher(true, impl)
	case "decrypt":
		runCipher(false, impl)
	default:
		usage()
	}
}
