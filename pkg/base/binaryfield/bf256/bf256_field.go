package bf256

import (
	"encoding/binary"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

const (
	NameF2e256       = "F2e256"
	fieldBytesF2e256 = 32
	fieldLimbsF2e256 = 4
)

var (
	field2e256Instance = &Field{}
	zero               = &FieldElement{}
	order, _           = saferith.ModulusFromHex("100000000000000000000000000000000")
)

var _ algebra.FiniteField[*Field, *FieldElement] = (*Field)(nil)

type Field struct{}

func NewField() *Field {
	return field2e256Instance
}

func (*Field) GetOperator(op algebra.Operator) (algebra.BinaryOperator[*FieldElement], bool) {
	//TODO implement me
	panic("implement me")
}

// === Basic Methods.

func (*Field) Name() string {
	return NameF2e256
}

func (*Field) Element() *FieldElement {
	return zero
}

func (*Field) Order() *saferith.Modulus {
	return order
}

func (*Field) FieldBytes() int {
	return fieldBytesF2e256
}

func (*Field) WideFieldBytes() int {
	return 2 * fieldBytesF2e256
}

func (*Field) Operators() []algebra.Operator {
	panic("implement me")
}

func (*Field) Random(prng io.Reader) (*FieldElement, error) {
	var buf [fieldBytesF2e256]byte
	if _, err := io.ReadFull(prng, buf[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't sample random F2e256 element")
	}
	el := &FieldElement{}
	el.V[0] = binary.LittleEndian.Uint64(buf[:8])
	el.V[1] = binary.LittleEndian.Uint64(buf[8:16])
	el.V[2] = binary.LittleEndian.Uint64(buf[16:24])
	el.V[3] = binary.LittleEndian.Uint64(buf[24:32])
	return el, nil
}

func (*Field) Hash(x []byte) (*FieldElement, error) {
	buf, err := hashing.Hash(base.RandomOracleHashFunction, x)
	if err != nil || len(buf) != fieldBytesF2e256 {
		return nil, errs.WrapHashing(err, "couldn't hash F2e256 element")
	}
	el := &FieldElement{}
	el.V[0] = binary.LittleEndian.Uint64(buf[:8])
	el.V[1] = binary.LittleEndian.Uint64(buf[8:16])
	el.V[2] = binary.LittleEndian.Uint64(buf[16:24])
	el.V[3] = binary.LittleEndian.Uint64(buf[24:32])
	return el, nil
}

func (*Field) Select(choice bool, x0, x1 *FieldElement) *FieldElement {
	el := x0.Clone()
	el.V[0] = ct.Select(utils.BoolTo[uint64](choice), el.V[0], x1.V[0])
	el.V[1] = ct.Select(utils.BoolTo[uint64](choice), el.V[1], x1.V[1])
	el.V[2] = ct.Select(utils.BoolTo[uint64](choice), el.V[2], x1.V[2])
	el.V[3] = ct.Select(utils.BoolTo[uint64](choice), el.V[3], x1.V[3])
	return el
}

// === Additive Group Methods.

func (*Field) Add(x algebra.AdditiveGroupoidElement[*Field, *FieldElement], ys ...algebra.AdditiveGroupoidElement[*Field, *FieldElement]) *FieldElement {
	res := x.Clone()
	for _, y := range ys {
		res = res.Add(y)
	}
	return res
}

func (*Field) AdditiveIdentity() *FieldElement {
	return &FieldElement{}
}

func (*Field) Sub(x algebra.AdditiveGroupElement[*Field, *FieldElement], ys ...algebra.AdditiveGroupElement[*Field, *FieldElement]) *FieldElement {
	res := x.Clone()
	for _, y := range ys {
		res = res.Sub(y)
	}
	return res
}

// === Multiplicative Group Methods.

func (*Field) Multiply(x *FieldElement, ys ...*FieldElement) *FieldElement {
	res := x.Clone()
	for _, y := range ys {
		res = res.Mul(y)
	}
	return res
}

func (*Field) MultiplicativeIdentity() *FieldElement {
	return &FieldElement{
		V: [fieldLimbsF2e256]uint64{1, 0, 0, 0},
	}
}

func (*Field) Div(x algebra.MultiplicativeGroupElement[*Field, *FieldElement], ys ...algebra.MultiplicativeGroupElement[*Field, *FieldElement]) (*FieldElement, error) {
	res := x.Clone()
	for _, y := range ys {
		var err error
		res, err = res.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot compute inverser")
		}
	}
	return res, nil
}

// === Ring methods.

func (*Field) QuadraticResidue(algebra.RingElement[*Field, *FieldElement]) (*FieldElement, error) {
	panic("not implemented")
}

func (*Field) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(2)
}

func (*Field) Addition() algebra.Addition[*FieldElement] {
	// TODO implement me
	panic("implement me")
}

func (*Field) Cardinality() *saferith.Modulus {
	return order
}

func (*Field) CoPrime(x *FieldElement, ys ...*FieldElement) bool {
	// TODO implement me
	panic("implement me")
}

func (*Field) GCD(x *FieldElement, ys ...*FieldElement) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*Field) LCM(x *FieldElement, ys ...*FieldElement) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*Field) Contains(_ *FieldElement) bool {
	return true
}

func (*Field) DiscreteExponentiation() algebra.DiscreteExponentiation[*FieldElement] {
	// TODO implement me
	panic("implement me")
}

func (*Field) ElementSize() int {
	return fieldBytesF2e256
}

func (*Field) WideElementSize() int {
	return 2 * fieldBytesF2e256
}

func (*Field) Equal(_ *Field) bool {
	return true
}

func (*Field) Exp(b, power *FieldElement) *FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*Field) HashCode() uint64 {
	return 1
}

func (*Field) Identity(under algebra.Operator) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*Field) IsDefinedUnder(operator algebra.Operator) bool {
	// TODO implement me
	panic("implement me")
}

func (*Field) Iter() <-chan *FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*Field) Mul(x algebra.MultiplicativeGroupoidElement[*Field, *FieldElement], ys ...algebra.MultiplicativeGroupoidElement[*Field, *FieldElement]) *FieldElement {
	z := x.Clone()
	for _, y := range ys {
		z = z.Mul(y.Unwrap())
	}

	return z
}

func (*Field) SimExp(bases []algebra.MultiplicativeGroupoidElement[*Field, *FieldElement], exponents []*saferith.Nat) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*Field) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[*Field, *FieldElement], exponent *saferith.Nat) *FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*Field) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[*Field, *FieldElement], exponents []*saferith.Nat) *FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*Field) Multiplication() algebra.Multiplication[*FieldElement] {
	// TODO implement me
	panic("implement me")
}

func (*Field) MultiplicativeGroup() algebra.MultiplicativeGroup[*Field, *FieldElement] {
	// TODO implement me
	panic("implement me")
}

func (*Field) Operate(operator algebra.Operator, x algebra.GroupoidElement[*Field, *FieldElement], ys ...algebra.GroupoidElement[*Field, *FieldElement]) (*FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (f *Field) Unwrap() *Field {
	return f
}
