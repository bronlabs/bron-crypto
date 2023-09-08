package pallas

import (
	"crypto/subtle"
	"io"

	"github.com/copperexchange/krypton/pkg/base/curves/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/pallas/impl/fp"
	"github.com/copperexchange/krypton/pkg/base/curves/pallas/impl/fq"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
)

type Ep struct {
	X *fp.Fp
	Y *fp.Fp
	Z *fp.Fp

	_ types.Incomparable
}

func (p *Ep) Random(reader io.Reader) *Ep {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (p *Ep) Hash(input []byte) *Ep {
	if input == nil {
		input = []byte{}
	}
	u := impl.ExpandMsgXmd(impl.EllipticPointHasherBlake2b(), input, []byte("pallas_XMD:BLAKE2b_SSWU_RO_"), 128)
	var buf [64]byte
	copy(buf[:], u[:64])
	u0 := new(fp.Fp).SetBytesWide(&buf)
	copy(buf[:], u[64:])
	u1 := new(fp.Fp).SetBytesWide(&buf)

	q0 := mapSswu(u0)
	q1 := mapSswu(u1)
	r1 := isoMap(q0)
	r2 := isoMap(q1)
	return p.Identity().Add(r1, r2)
}

func (p *Ep) Identity() *Ep {
	p.X = new(fp.Fp).SetZero()
	p.Y = new(fp.Fp).SetZero()
	p.Z = new(fp.Fp).SetZero()
	return p
}

func (p *Ep) Generator() *Ep {
	p.X = new(fp.Fp).SetOne()
	p.Y = &fp.Fp{0x2f474795455d409d, 0xb443b9b74b8255d9, 0x270c412f2c9a5d66, 0x8e00f71ba43dd6b}
	p.Z = new(fp.Fp).SetOne()
	return p
}

func (p *Ep) IsIdentity() bool {
	return p.Z.IsZero()
}

func (p *Ep) Double(other *Ep) *Ep {
	if other.IsIdentity() {
		p.Set(other)
		return p
	}
	r := new(Ep)
	// essentially paraphrased https://github.com/MinaProtocol/c-reference-signer/blob/master/crypto.c#L306-L337
	a := new(fp.Fp).Square(other.X)

	b := new(fp.Fp).Square(other.Y)
	c := new(fp.Fp).Square(b)
	r.X = new(fp.Fp).Add(other.X, b)
	r.Y = new(fp.Fp).Square(r.X)
	r.Z = new(fp.Fp).Sub(r.Y, a)
	r.X.Sub(r.Z, c)
	d := new(fp.Fp).Double(r.X)
	e := new(fp.Fp).Mul(three, a)
	f := new(fp.Fp).Square(e)
	r.Y.Double(d)
	r.X.Sub(f, r.Y)
	r.Y.Sub(d, r.X)
	f.Mul(eight, c)
	r.Z.Mul(e, r.Y)
	r.Y.Sub(r.Z, f)
	f.Mul(other.Y, other.Z)
	r.Z.Double(f)
	p.Set(r)
	return p
}

func (p *Ep) Neg(other *Ep) *Ep {
	p.X = new(fp.Fp).Set(other.X)
	p.Y = new(fp.Fp).Neg(other.Y)
	p.Z = new(fp.Fp).Set(other.Z)
	return p
}

func (p *Ep) Add(lhs, rhs *Ep) *Ep {
	if lhs.IsIdentity() {
		return p.Set(rhs)
	}
	if rhs.IsIdentity() {
		return p.Set(lhs)
	}
	z1z1 := new(fp.Fp).Square(lhs.Z)
	z2z2 := new(fp.Fp).Square(rhs.Z)
	u1 := new(fp.Fp).Mul(lhs.X, z2z2)
	u2 := new(fp.Fp).Mul(rhs.X, z1z1)
	s1 := new(fp.Fp).Mul(lhs.Y, z2z2)
	s1.Mul(s1, rhs.Z)
	s2 := new(fp.Fp).Mul(rhs.Y, z1z1)
	s2.Mul(s2, lhs.Z)

	if !u1.Equal(u2) {
		h := new(fp.Fp).Sub(u2, u1)
		i := new(fp.Fp).Double(h)
		i.Square(i)
		j := new(fp.Fp).Mul(i, h)
		r := new(fp.Fp).Sub(s2, s1)
		r.Double(r)
		v := new(fp.Fp).Mul(u1, i)
		x3 := new(fp.Fp).Square(r)
		x3.Sub(x3, j)
		x3.Sub(x3, new(fp.Fp).Double(v))
		s1.Mul(s1, j)
		s1.Double(s1)
		y3 := new(fp.Fp).Mul(r, new(fp.Fp).Sub(v, x3))
		y3.Sub(y3, s1)
		z3 := new(fp.Fp).Add(lhs.Z, rhs.Z)
		z3.Square(z3)
		z3.Sub(z3, z1z1)
		z3.Sub(z3, z2z2)
		z3.Mul(z3, h)
		p.X = new(fp.Fp).Set(x3)
		p.Y = new(fp.Fp).Set(y3)
		p.Z = new(fp.Fp).Set(z3)

		return p
	}

	if s1.Equal(s2) {
		return p.Double(lhs)
	} else {
		return p.Identity()
	}
}

func (p *Ep) Sub(lhs, rhs *Ep) *Ep {
	return p.Add(lhs, new(Ep).Neg(rhs))
}

func (p *Ep) Mul(point *Ep, scalar *fq.Fq) *Ep {
	bytes_ := scalar.Bytes()
	precomputed := [16]*Ep{}
	precomputed[0] = new(Ep).Identity()
	precomputed[1] = new(Ep).Set(point)
	for i := 2; i < 16; i += 2 {
		precomputed[i] = new(Ep).Double(precomputed[i>>1])
		precomputed[i+1] = new(Ep).Add(precomputed[i], point)
	}
	p.Identity()
	for i := 0; i < 256; i += 4 {
		// Brouwer / windowing method. window size of 4.
		for j := 0; j < 4; j++ {
			p.Double(p)
		}
		window := bytes_[32-1-i>>3] >> (4 - i&0x04) & 0x0F
		p.Add(p, precomputed[window])
	}
	return p
}

func (p *Ep) Equal(other *Ep) bool {
	// warning: requires converting both to affine
	// could save slightly by modifying one so that its z-value equals the other
	// this would save one inversion and a handful of multiplications
	// but this is more subtle and error-prone, so going to just convert both to affine.
	lhs := new(Ep).Set(p)
	rhs := new(Ep).Set(other)
	lhs.toAffine()
	rhs.toAffine()
	return lhs.X.Equal(rhs.X) && lhs.Y.Equal(rhs.Y)
}

func (p *Ep) Set(other *Ep) *Ep {
	// check is identity or on curve
	p.X = new(fp.Fp).Set(other.X)
	p.Y = new(fp.Fp).Set(other.Y)
	p.Z = new(fp.Fp).Set(other.Z)
	return p
}

func (p *Ep) toAffine() {
	// mutates `p` in-place to convert it to "affine" form.
	if p.IsIdentity() {
		// TODO: make constant time
		// warning: control flow / not constant-time
		p.X.SetZero()
		p.Y.SetZero()
		p.Z.SetOne()
	}
	zInv3, _ := new(fp.Fp).Invert(p.Z) // z is necessarily nonzero
	zInv2 := new(fp.Fp).Square(zInv3)
	zInv3.Mul(zInv3, zInv2)
	p.X.Mul(p.X, zInv2)
	p.Y.Mul(p.Y, zInv3)
	p.Z.SetOne()
}

func (p *Ep) ToAffineCompressed() []byte {
	// Use ZCash encoding where infinity is all zeros
	// and the top bit represents the sign of y and the
	// remainder represent the x-coordinate
	var inf [32]byte
	p1 := new(Ep).Set(p)
	p1.toAffine()
	x := p1.X.Bytes()
	x[31] |= (p1.Y.Bytes()[0] & 1) << 7
	subtle.ConstantTimeCopy(bool2int[p1.IsIdentity()], x[:], inf[:])
	return x[:]
}

func (p *Ep) ToAffineUncompressed() []byte {
	p1 := new(Ep).Set(p)
	p1.toAffine()
	x := p1.X.Bytes()
	y := p1.Y.Bytes()
	return append(x[:], y[:]...)
}

func (p *Ep) FromAffineCompressed(bytes_ []byte) (*Ep, error) {
	if len(bytes_) != 32 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}

	var input [32]byte
	copy(input[:], bytes_)
	sign := (input[31] >> 7) & 1
	input[31] &= 0x7F

	x := new(fp.Fp)
	if _, err := x.SetBytes(&input); err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}
	rhs := rhsPallas(x)
	if _, square := rhs.Sqrt(rhs); !square {
		return nil, errs.NewInvalidCoordinates("rhs of given x-coordinate is not a square")
	}
	if rhs.Bytes()[0]&1 != sign {
		rhs.Neg(rhs)
	}
	p.X = x
	p.Y = rhs
	p.Z = new(fp.Fp).SetOne()
	if !p.IsOnCurve() {
		return nil, errs.NewInvalidType("invalid point")
	}
	return p, nil
}

func (p *Ep) FromAffineUncompressed(bytes_ []byte) (*Ep, error) {
	if len(bytes_) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	p.Z = new(fp.Fp).SetOne()
	p.X = new(fp.Fp)
	p.Y = new(fp.Fp)
	var x, y [32]byte
	copy(x[:], bytes_[:32])
	copy(y[:], bytes_[32:])
	if _, err := p.X.SetBytes(&x); err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x")
	}
	if _, err := p.Y.SetBytes(&y); err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set y")
	}
	if !p.IsOnCurve() {
		return nil, errs.NewMembershipError("invalid point")
	}
	return p, nil
}

func (Ep) CurveName() string {
	return "pallas"
}

func (p *Ep) GetX() *fp.Fp {
	t := new(Ep).Set(p)
	t.toAffine()
	return new(fp.Fp).Set(t.X)
}

func (p *Ep) GetY() *fp.Fp {
	t := new(Ep).Set(p)
	t.toAffine()
	return new(fp.Fp).Set(t.Y)
}

func (p *Ep) IsOnCurve() bool {
	// y^2 = x^3 + axz^4 + bz^6
	// a = 0
	// b = 5
	z2 := new(fp.Fp).Square(p.Z)
	z4 := new(fp.Fp).Square(z2)
	z6 := new(fp.Fp).Mul(z2, z4)
	x2 := new(fp.Fp).Square(p.X)
	x3 := new(fp.Fp).Mul(x2, p.X)

	lhs := new(fp.Fp).Square(p.Y)
	rhs := new(fp.Fp).SetUint64(5)
	rhs.Mul(rhs, z6)
	rhs.Add(rhs, x3)
	return p.Z.IsZero() || lhs.Equal(rhs)
}

func (p *Ep) CMove(lhs, rhs *Ep, condition int) *Ep {
	p.X = new(fp.Fp).CMove(lhs.X, rhs.X, condition)
	p.Y = new(fp.Fp).CMove(lhs.Y, rhs.Y, condition)
	p.Z = new(fp.Fp).CMove(lhs.Z, rhs.Z, condition)
	return p
}
