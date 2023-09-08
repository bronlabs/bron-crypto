package test_utils

import (
	"crypto/elliptic"
	"crypto/subtle"
	"hash"
	"math/big"
	"sync"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
)

// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#appendix-G.2.1
func Osswu3mod4(u *big.Int, p *SswuParams) (x, y *big.Int) {
	params := p.Params
	field := NewField(p.Params.P)

	tv1 := field.NewElement(u)
	tv1 = tv1.Mul(tv1)                    // tv1 = u^2
	tv3 := field.NewElement(p.Z).Mul(tv1) // tv3 = Z * tv1
	tv2 := tv3.Mul(tv3)                   // tv2 = tv3^2
	xd := tv2.Add(tv3)                    // xd = tv2 + tv3
	x1n := xd.Add(field.One())            // x1n = (xd + 1)
	x1n = x1n.Mul(field.NewElement(p.B))  // x1n * B
	aNeg := field.NewElement(p.A).Neg()
	xd = xd.Mul(aNeg) // xd = -A * xd

	if xd.Value.Cmp(big.NewInt(0)) == 0 {
		xd = field.NewElement(p.Z).Mul(field.NewElement(p.A)) // xd = Z * A
	}

	tv2 = xd.Mul(xd)                     // tv2 = xd^2
	gxd := tv2.Mul(xd)                   // gxd = tv2 * xd
	tv2 = tv2.Mul(field.NewElement(p.A)) // tv2 = A * tv2

	gx1 := x1n.Mul(x1n)                  // gx1 = x1n^2
	gx1 = gx1.Add(tv2)                   // gx1 = gx1 + tv2
	gx1 = gx1.Mul(x1n)                   // gx1 = gx1 * x1n
	tv2 = gxd.Mul(field.NewElement(p.B)) // tv2 = B * gxd
	gx1 = gx1.Add(tv2)                   // gx1 = gx1 + tv2

	tv4 := gxd.Mul(gxd) // tv4 = gxd^2
	tv2 = gx1.Mul(gxd)  // tv2 = gx1 * gxd
	tv4 = tv4.Mul(tv2)  // tv4 = tv4 * tv2

	y1 := tv4.Pow(field.NewElement(p.C1))
	y1 = y1.Mul(tv2)    // y1 = y1 * tv2
	x2n := tv3.Mul(x1n) // x2n = tv3 * x1n

	y2 := y1.Mul(field.NewElement(p.C2)) // y2 = y1 * c2
	y2 = y2.Mul(tv1)                     // y2 = y2 * tv1
	y2 = y2.Mul(field.NewElement(u))     // y2 = y2 * u

	tv2 = y1.Mul(y1) // tv2 = y1^2

	tv2 = tv2.Mul(gxd) // tv2 = tv2 * gxd

	e2 := tv2.Value.Cmp(gx1.Value) == 0

	// If e2, x = x1, else x = x2
	if e2 {
		x = x1n.Value
	} else {
		x = x2n.Value
	}
	// xn / xd
	x.Mul(x, new(big.Int).ModInverse(xd.Value, params.P))
	x.Mod(x, params.P)

	// If e2, y = y1, else y = y2
	if e2 {
		y = y1.Value
	} else {
		y = y2.Value
	}

	uBytes := u.Bytes()
	yBytes := y.Bytes()

	usign := uBytes[len(uBytes)-1] & 1
	ysign := yBytes[len(yBytes)-1] & 1

	// Fix sign of y
	if usign != ysign {
		y.Neg(y)
		y.Mod(y, params.P)
	}

	return x, y
}

func ExpandMsgXmd(h hash.Hash, msg, domain []byte, outLen int) ([]byte, error) {
	domainLen := uint8(len(domain))
	if domainLen > 255 {
		return nil, errs.NewInvalidLength("invalid domain length")
	}
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		subtle.XORBytes(tmp, b0, bi)
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])
	return out[:outLen], nil
}

type SswuParams struct {
	Params          *elliptic.CurveParams
	C1, C2, A, B, Z *big.Int

	_ helper_types.Incomparable
}

type MockReader struct {
	index int
	seed  []byte

	_ helper_types.Incomparable
}

var (
	mockRngInitonce sync.Once
	mockRng         MockReader
)

func NewMockReader() {
	mockRng.index = 0
	mockRng.seed = make([]byte, 32)
	for i := range mockRng.seed {
		mockRng.seed[i] = 1
	}
}

func TestRng() *MockReader {
	mockRngInitonce.Do(NewMockReader)
	return &mockRng
}

func (m *MockReader) Read(p []byte) (n int, err error) {
	limit := len(m.seed)
	for i := range p {
		p[i] = m.seed[m.index]
		m.index++
		m.index %= limit
	}
	n = len(p)
	return n, nil
}
