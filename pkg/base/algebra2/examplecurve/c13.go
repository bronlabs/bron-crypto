package examplecurve

// import (
// 	"fmt"

// 	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
// 	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/curves"
// )

// var (
// 	C13CurveInstance = &C13Curve{}

// 	_ curves.GenericCurve[*C13Point, *Z13Element, *Z5Element] = C13CurveInstance
// 	_ curves.Point[*C13Point, *Z13Element, *Z5Element]        = (*C13Point)(nil)
// )

// type C13Curve struct{}

// func (c *C13Curve) Name() string {
// 	return "C13"
// }

// func (c *C13Curve) Order() algebra.Cardinal {
// 	panic("implement me")
// }

// func (c *C13Curve) OpIdentity() *C13Point {
// 	return &C13Point{
// 		X: Z13Instance.Zero(),
// 		Y: Z13Instance.One(),
// 		Z: Z13Instance.Zero(),
// 	}
// }

// func (c *C13Curve) FromAffineCompressed(b []byte) (*C13Point, error) {
// 	panic("implement me")
// }

// func (c *C13Curve) FromAffineUncompressed(b []byte) (*C13Point, error) {
// 	panic("implement me")
// }

// func (c *C13Curve) NewPoint(x, y *Z13Element) (*C13Point, error) {
// 	return &C13Point{
// 		X: x,
// 		Y: y,
// 		Z: Z13Instance.One(),
// 	}, nil
// }

// func (c *C13Curve) PrimeSubGroupGenerator() *C13Point {
// 	return &C13Point{
// 		X: &Z13Element{V: 4},
// 		Y: &Z13Element{V: 4},
// 		Z: Z13Instance.One(),
// 	}
// }

// type C13Point struct {
// 	X *Z13Element
// 	Y *Z13Element
// 	Z *Z13Element
// }

// func (p *C13Point) MarshalBinary() (data []byte, err error) {
// 	panic("implement me")
// }

// func (p *C13Point) UnmarshalBinary(data []byte) error {
// 	panic("implement me")
// }

// func (p *C13Point) Clone() *C13Point {
// 	return &C13Point{
// 		X: p.X.Clone(),
// 		Y: p.Y.Clone(),
// 		Z: p.Z.Clone(),
// 	}
// }

// func (p *C13Point) Equal(rhs *C13Point) bool {
// 	lx := p.X.Mul(rhs.Z)
// 	rx := rhs.X.Mul(p.Z)
// 	ly := p.Y.Mul(rhs.Z)
// 	ry := rhs.Y.Mul(p.Z)

// 	return lx.Equal(rx) && ly.Equal(ry)
// }

// func (p *C13Point) HashCode() uint64 {
// 	panic("implement me")
// }

// func (p *C13Point) Structure() algebra.Structure[*C13Point] {
// 	return C13CurveInstance
// }

// func (p *C13Point) Op(rhs *C13Point) *C13Point {
// 	x1 := p.X
// 	y1 := p.Y
// 	z1 := p.Z
// 	x2 := rhs.X
// 	y2 := rhs.Y
// 	z2 := rhs.Z

// 	a := Z13Instance.One()
// 	b3 := Z13Instance.Zero()
// 	t0 := x1.Mul(x2)
// 	t1 := y1.Mul(y2)
// 	t2 := z1.Mul(z2)
// 	t3 := x1.Add(y1)
// 	t4 := x2.Add(y2)
// 	t3 = t3.Mul(t4)
// 	t4 = t0.Add(t1)
// 	t3 = t3.Sub(t4)
// 	t4 = x1.Add(z1)
// 	t5 := x2.Add(z2)
// 	t4 = t4.Mul(t5)
// 	t5 = t0.Add(t2)
// 	t4 = t4.Sub(t5)
// 	t5 = y1.Add(z1)
// 	x3 := y2.Add(z2)
// 	t5 = t5.Mul(x3)
// 	x3 = t1.Add(t2)
// 	t5 = t5.Sub(x3)
// 	z3 := a.Mul(t4)
// 	x3 = b3.Mul(t2)
// 	z3 = x3.Add(z3)
// 	x3 = t1.Sub(z3)
// 	z3 = t1.Add(z3)
// 	y3 := x3.Mul(z3)
// 	t1 = t0.Add(t0)
// 	t1 = t1.Add(t0)
// 	t2 = a.Mul(t2)
// 	t4 = b3.Mul(t4)
// 	t1 = t1.Add(t2)
// 	t2 = t0.Sub(t2)
// 	t2 = a.Mul(t2)
// 	t4 = t4.Add(t2)
// 	t0 = t1.Mul(t4)
// 	y3 = y3.Add(t0)
// 	t0 = t5.Mul(t4)
// 	x3 = t3.Mul(x3)
// 	x3 = x3.Sub(t0)
// 	t0 = t3.Mul(t1)
// 	z3 = t5.Mul(z3)
// 	z3 = z3.Add(t0)

// 	return &C13Point{
// 		X: x3,
// 		Y: y3,
// 		Z: z3,
// 	}
// }

// func (p *C13Point) Order() algebra.Cardinal {
// 	panic("implement me")
// }

// func (p *C13Point) IsOpIdentity() bool {
// 	return p.Z.IsZero()
// }

// func (p *C13Point) OpInv() *C13Point {
// 	return &C13Point{
// 		X: p.X,
// 		Y: p.Y.Neg(),
// 		Z: p.Z,
// 	}
// }

// func (p *C13Point) Coordinates() []*Z13Element {
// 	x, err := p.X.TryDiv(p.Z)
// 	if err != nil {
// 		panic(err)
// 	}
// 	y, err := p.Y.TryDiv(p.Z)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return []*Z13Element{x, y}
// }

// func (p *C13Point) ToAffineCompressed() []byte {
// 	panic("implement me")
// }

// func (p *C13Point) ToAffineUncompressed() []byte {
// 	panic("implement me")
// }

// func (p *C13Point) AffineX() *Z13Element {
// 	return p.Coordinates()[0]
// }

// func (p *C13Point) AffineY() *Z13Element {
// 	return p.Coordinates()[0]
// }

// func (p *C13Point) ScalarMul(sc *Z5Element) *C13Point {
// 	r := C13CurveInstance.OpIdentity()
// 	for i := uint64(0); i < sc.V; i++ {
// 		r = r.Op(p)
// 	}

// 	return r
// }

// func (p *C13Point) String() string {
// 	if p.Z.IsZero() {
// 		return "(0, 1, 0)"
// 	}

// 	x, _ := p.X.TryDiv(p.Z)
// 	y, _ := p.Y.TryDiv(p.Z)
// 	return fmt.Sprintf("(%d, %d, 1)", x.V, y.V)
// }
