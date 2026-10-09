package qr

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Texts of every length from 1 to the version 10 limit, so each version and
// both count field widths are drawn.
func samples() []string {
	var out []string
	for n := 1; n <= 213; n += 7 {
		out = append(out, strings.Repeat("otpauth://totp/portash:x?secret=ABC", 7)[:n])
	}
	return append(out, "otpauth://totp/portash%20demo.example.com:admin?algorithm=SHA1&digits=6&issuer=portash+demo.example.com&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
}

func TestVersionAndSize(t *testing.T) {
	for _, tc := range []struct{ n, version int }{{14, 1}, {15, 2}, {26, 2}, {27, 3}, {152, 8}, {153, 9}, {180, 9}, {181, 10}, {213, 10}} {
		c, err := Encode(strings.Repeat("a", tc.n))
		if err != nil {
			t.Fatal(tc.n, err)
		}
		if c.Size != 17+4*tc.version {
			t.Errorf("%d bytes: size %d, want version %d", tc.n, c.Size, tc.version)
		}
	}
	if _, err := Encode(strings.Repeat("a", 214)); err != ErrTooLong {
		t.Errorf("214 bytes: %v", err)
	}
}

func TestRSKnownVector(t *testing.T) {
	// "HELLO WORLD" 1-M from the QR code tutorial (thonky.com).
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, 10); !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTerminal(t *testing.T) {
	c, _ := Encode("hi")
	var b bytes.Buffer
	if err := c.WriteTerminal(&b); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != (c.Size+4+1)/2 || strings.Count(lines[0], "▀") != c.Size+4 {
		t.Errorf("%d lines, %d blocks in the first", len(lines), strings.Count(lines[0], "▀"))
	}
}

// With QR_PNG_DIR set, writes every sample in every mask as a PNG, plus
// a list of the expected texts, for checking with a real decoder.
func TestWritePNGs(t *testing.T) {
	dir := os.Getenv("QR_PNG_DIR")
	if dir == "" {
		t.Skip("QR_PNG_DIR not set")
	}
	var list strings.Builder
	for i, s := range samples() {
		for m := -1; m < 8; m++ {
			c, err := encode([]byte(s), m)
			if err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("%03d_%d.png", i, m+1)
			writePNG(t, filepath.Join(dir, name), c)
			fmt.Fprintf(&list, "%s\t%s\n", name, s)
		}
	}
	os.WriteFile(filepath.Join(dir, "expected.tsv"), []byte(list.String()), 0o644)
}

func writePNG(t *testing.T, path string, c *Code) {
	const scale, quiet = 6, 4
	n := (c.Size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			mx, my := x/scale-quiet, y/scale-quiet
			v := uint8(255)
			if mx >= 0 && my >= 0 && mx < c.Size && my < c.Size && c.Dark(mx, my) {
				v = 0
			}
			img.SetGray(x, y, color.Gray{v})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}
