package implng

type FieldArithmetic[FE any] interface {
	SetZero(out *FE) *FE
	SetOne(out *FE) *FE
	SetBytes(out *FE, data []byte) (*FE, bool)
	SetBytesWide(out *FE, data []byte) *FE
	Add(out, lhs, rhs *FE) *FE
	Double(out, x *FE) *FE
	Sub(out, lhs, rhs *FE) *FE
	Neg(out, x *FE) *FE
	Mul(out, lhs, rhs *FE) *FE
	Square(out, x *FE) *FE
	Div(out, lhs, rhs *FE) *FE
	Inv(out, x *FE) (*FE, uint64)
	Sqrt(out, x *FE) (*FE, uint64)
	CMove(out *FE, choice uint64, lhs, rhs *FE) *FE

	IsZero(x *FE) uint64
	IsOne(x *FE) uint64
	IsGreater(lhs, rhs *FE) uint64
	IsEqual(lhs, rhs *FE) uint64
	IsOdd(x *FE) uint64
	ToBytes(x *FE) []byte
}
