// Package qr draws QR codes in a terminal, so `portash totp enroll` can show
// the authenticator link as something a phone can scan. It covers what an
// otpauth:// link needs and no more: byte mode, error correction level M,
// versions 1 to 10 (up to 213 bytes).
package qr

import (
	"errors"
	"io"
	"strings"
)

// Code is a QR code: Size×Size modules, true = dark.
type Code struct {
	Size    int
	modules [][]bool
	isFunc  [][]bool
}

// Dark reports whether the module at column x, row y is dark.
func (c *Code) Dark(x, y int) bool { return c.modules[y][x] }

// ErrTooLong means the text doesn't fit in a version 10 code.
var ErrTooLong = errors.New("qr: text too long")

// Error correction level M, per version: EC codewords per block and the
// blocks as (count, data codewords) groups.
type block struct{ count, data int }

var versions = [...]struct {
	ec     int
	groups []block
}{
	{},
	{10, []block{{1, 16}}},
	{16, []block{{1, 28}}},
	{26, []block{{1, 44}}},
	{18, []block{{2, 32}}},
	{24, []block{{2, 43}}},
	{16, []block{{4, 27}}},
	{18, []block{{4, 31}}},
	{22, []block{{2, 38}, {2, 39}}},
	{22, []block{{3, 36}, {2, 37}}},
	{26, []block{{4, 43}, {1, 44}}},
}

var alignment = [...][]int{
	{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
	{6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
}

func dataCodewords(v int) int {
	n := 0
	for _, g := range versions[v].groups {
		n += g.count * g.data
	}
	return n
}

func countBits(v int) int {
	if v <= 9 {
		return 8
	}
	return 16
}

// Encode makes a QR code for text, in the smallest version it fits.
func Encode(text string) (*Code, error) { return encode([]byte(text), -1) }

// encode with mask -1 picks the mask with the lowest penalty.
func encode(data []byte, mask int) (*Code, error) {
	v := 1
	for ; v <= 10; v++ {
		if 4+countBits(v)+8*len(data) <= dataCodewords(v)*8 {
			break
		}
	}
	if v > 10 {
		return nil, ErrTooLong
	}

	// Byte mode, count, data, terminator, padding.
	var bits bitBuffer
	bits.add(0b0100, 4)
	bits.add(len(data), countBits(v))
	for _, b := range data {
		bits.add(int(b), 8)
	}
	capBits := dataCodewords(v) * 8
	bits.add(0, min(4, capBits-len(bits)))
	bits.add(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		bits.add(pad, 8)
	}
	codewords := interleave(v, bits.bytes())

	size := 17 + 4*v
	c := &Code{Size: size, modules: grid(size), isFunc: grid(size)}
	c.drawFunctionPatterns(v)
	c.drawCodewords(codewords)
	if mask < 0 {
		best := -1
		for m := 0; m < 8; m++ {
			c.applyMask(m)
			c.drawFormat(m)
			if p := c.penalty(); best < 0 || p < best {
				best, mask = p, m
			}
			c.applyMask(m) // XOR again undoes it
		}
	}
	c.applyMask(mask)
	c.drawFormat(mask)
	return c, nil
}

func grid(n int) [][]bool {
	g := make([][]bool, n)
	for i := range g {
		g[i] = make([]bool, n)
	}
	return g
}

type bitBuffer []bool

func (b *bitBuffer) add(v, n int) {
	for i := n - 1; i >= 0; i-- {
		*b = append(*b, v>>i&1 == 1)
	}
}

func (b bitBuffer) bytes() []byte {
	out := make([]byte, len(b)/8)
	for i, bit := range b {
		if bit {
			out[i/8] |= 0x80 >> (i % 8)
		}
	}
	return out
}

// interleave splits the data into blocks, adds each block's Reed-Solomon
// codewords, and interleaves them as the standard requires.
func interleave(v int, data []byte) []byte {
	ecLen := versions[v].ec
	var blocks, ecs [][]byte
	for _, g := range versions[v].groups {
		for i := 0; i < g.count; i++ {
			blocks = append(blocks, data[:g.data])
			ecs = append(ecs, rsRemainder(data[:g.data], ecLen))
			data = data[g.data:]
		}
	}
	var out []byte
	for i := 0; ; i++ {
		added := false
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
				added = true
			}
		}
		if !added {
			break
		}
	}
	for i := 0; i < ecLen; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	return out
}

// GF(256) with the QR polynomial x^8+x^4+x^3+x^2+1.
var gfExp, gfLog = func() (e [512]byte, l [256]byte) {
	x := 1
	for i := 0; i < 255; i++ {
		e[i] = byte(x)
		l[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		e[i] = e[i-255]
	}
	return
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func rsRemainder(data []byte, n int) []byte {
	// Generator (x - a^0)(x - a^1)...(x - a^(n-1)), highest coefficient
	// (always 1) left out.
	gen := make([]byte, n)
	gen[n-1] = 1
	root := byte(1)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			gen[j] = gfMul(gen[j], root)
			if j+1 < n {
				gen[j] ^= gen[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	rem := make([]byte, n)
	for _, b := range data {
		f := b ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for j := range rem {
			rem[j] ^= gfMul(gen[j], f)
		}
	}
	return rem
}

func (c *Code) set(x, y int, dark bool) {
	c.modules[y][x] = dark
	c.isFunc[y][x] = true
}

func (c *Code) drawFunctionPatterns(v int) {
	n := c.Size
	for i := 0; i < n; i++ {
		c.set(6, i, i%2 == 0)
		c.set(i, 6, i%2 == 0)
	}
	for _, p := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := p[0]+dx, p[1]+dy
				if x < 0 || y < 0 || x >= n || y >= n {
					continue
				}
				d := max(abs(dx), abs(dy))
				c.set(x, y, d != 2 && d != 4)
			}
		}
	}
	pos := alignment[v]
	for i, ax := range pos {
		for j, ay := range pos {
			last := len(pos) - 1
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue // under a finder pattern
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					c.set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	c.drawFormat(0) // reserves the format areas; redrawn with the real mask
	if v >= 7 {
		rem := v
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := v<<12 | rem
		for i := 0; i < 18; i++ {
			dark := bits>>i&1 == 1
			a, b := n-11+i%3, i/3
			c.set(a, b, dark)
			c.set(b, a, dark)
		}
	}
}

func (c *Code) drawFormat(mask int) {
	data := 0<<3 | mask // level M is 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	n := c.Size
	for i := 0; i <= 5; i++ {
		c.set(8, i, bit(i))
	}
	c.set(8, 7, bit(6))
	c.set(8, 8, bit(7))
	c.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		c.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		c.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		c.set(8, n-15+i, bit(i))
	}
	c.set(8, n-8, true)
}

func (c *Code) drawCodewords(data []byte) {
	n := c.Size
	i := 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if !c.isFunc[y][x] && i < len(data)*8 {
					c.modules[y][x] = data[i/8]>>(7-i%8)&1 == 1
					i++
				}
			}
		}
	}
}

func (c *Code) applyMask(m int) {
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.isFunc[y][x] {
				continue
			}
			var flip bool
			switch m {
			case 0:
				flip = (x+y)%2 == 0
			case 1:
				flip = y%2 == 0
			case 2:
				flip = x%3 == 0
			case 3:
				flip = (x+y)%3 == 0
			case 4:
				flip = (x/3+y/2)%2 == 0
			case 5:
				flip = x*y%2+x*y%3 == 0
			case 6:
				flip = (x*y%2+x*y%3)%2 == 0
			case 7:
				flip = ((x+y)%2+x*y%3)%2 == 0
			}
			if flip {
				c.modules[y][x] = !c.modules[y][x]
			}
		}
	}
}

// penalty scores how hard the code is to scan (lower is better).
func (c *Code) penalty() int {
	n := c.Size
	p := 0
	at := func(x, y int, row bool) bool {
		if row {
			return c.modules[y][x]
		}
		return c.modules[x][y]
	}
	finder := []bool{true, false, true, true, true, false, true}
	for _, row := range []bool{true, false} {
		for y := 0; y < n; y++ {
			run := 0
			for x := 0; x < n; x++ {
				if x > 0 && at(x, y, row) == at(x-1, y, row) {
					run++
				} else {
					run = 1
				}
				if run == 5 {
					p += 3
				} else if run > 5 {
					p++
				}
				// 1:1:3:1:1 with 4 light modules on one side
				if x+7 <= n {
					match := true
					for k, d := range finder {
						if at(x+k, y, row) != d {
							match = false
							break
						}
					}
					if match && (light(at, x-4, x, y, row, n) || light(at, x+7, x+11, y, row, n)) {
						p += 40
					}
				}
			}
		}
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if c.modules[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				d := c.modules[y][x]
				if d == c.modules[y][x+1] && d == c.modules[y+1][x] && d == c.modules[y+1][x+1] {
					p += 3
				}
			}
		}
	}
	p += abs(dark*20-n*n*10) / (n * n) * 10
	return p
}

// light reports whether modules from..to-1 on the line are all light,
// counting those outside the code as light.
func light(at func(int, int, bool) bool, from, to, y int, row bool, n int) bool {
	for x := from; x < to; x++ {
		if x >= 0 && x < n && at(x, y, row) {
			return false
		}
	}
	return true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// WriteTerminal draws the code with a 2-module quiet zone, two rows per text
// line (half blocks), in explicit black and white so it scans the same on
// light and dark terminal themes.
func (c *Code) WriteTerminal(w io.Writer) error {
	const quiet = 2
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.modules[y][x]
	}
	total := c.Size + 2*quiet
	var b strings.Builder
	for y := 0; y < total; y += 2 {
		for x := 0; x < total; x++ {
			fg, bg := "97", "107" // top / bottom module: white
			if dark(x, y) {
				fg = "30"
			}
			if dark(x, y+1) {
				bg = "40"
			}
			b.WriteString("\x1b[" + fg + ";" + bg + "m▀")
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
