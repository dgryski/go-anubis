package anubis

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

var _ cipher.Block = (*Cipher)(nil)

func TestCipher(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	plain, _ := hex.DecodeString("00000000000000000000000000000000")

	// vectors from set 3 of https://www.gnu.org/software/gnu-crypto/vectors/anubis-test-vectors-128.txt
	var tests = []struct {
		n    int
		want string
	}{
		{1, "0A58F9C567657DEE8D957B1071DA8695"},
		{100, "F912D9F666248A1BA2B2E7EBA57007A4"},
		{1000, "DB85278E8649A29D97A5FD34F0B572B5"},
	}

	c := New(key)
	for _, tt := range tests {
		src := make([]byte, len(plain))
		copy(src, plain)

		for i := 0; i < tt.n; i++ {
			c.Encrypt(src, src)
		}

		want, _ := hex.DecodeString(tt.want)
		if !bytes.Equal(src, want) {
			t.Errorf("Encrypt-%d(%x)=%x, want %x", tt.n, plain, src, want)
		}

		for i := 0; i < tt.n; i++ {
			c.Decrypt(src, src)
		}

		if !bytes.Equal(src, plain) {
			t.Errorf("Decrypt-%d(%x)=%x, want %x", tt.n, want, src, plain)
		}
	}
}
