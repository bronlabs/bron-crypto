package bf128

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
	Name       = "GF2e128"
	fieldBytes = 16
	fieldLimbs = 2
)

var (
	field2e128Instance = &Field{}
	zero               = &FieldElement{}
	one                = &FieldElement{V: [fieldLimbs]uint64{1, 0}}
	order, _           = saferith.ModulusFromHex("10000000000000000")
)

var _ algebra.AbstractFiniteField[*Field, *FieldElement] = (*Field)(nil)

type Field struct{}

func NewField() *Field {
	return field2e128Instance
}

// === Basic Methods.

func (*Field) Name() string {
	return Name
}

func (*Field) Element() *FieldElement {
	return zero
}

func (*Field) Order() *saferith.Modulus {
	return order
}

func (*Field) FieldBytes() int {
	return fieldBytes
}

func (*Field) WideFieldBytes() int {
	return 2 * fieldBytes
}

func (*Field) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (*Field) OperateOver(operator algebra.Operator, xs ...*FieldElement) (*FieldElement, error) {
	panic("not implemented")
}

func (*Field) Random(prng io.Reader) (*FieldElement, error) {
	var buf [fieldBytes]byte
	if _, err := io.ReadFull(prng, buf[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't sample random F2e128 element")
	}
	el := &FieldElement{}
	el.V[0] = binary.LittleEndian.Uint64(buf[:8])
	el.V[1] = binary.LittleEndian.Uint64(buf[8:16])
	return el, nil
}

func (*Field) Hash(x []byte) (*FieldElement, error) {
	buf, err := hashing.Hash(base.RandomOracleHashFunction, x)
	if err != nil || len(buf) != fieldBytes {
		return nil, errs.WrapHashing(err, "couldn't hash F2e128 element")
	}
	el := &FieldElement{}
	el.V[0] = binary.LittleEndian.Uint64(buf[:8])
	el.V[1] = binary.LittleEndian.Uint64(buf[8:16])
	return el, nil
}

func (*Field) Select(choice bool, x0, x1 *FieldElement) *FieldElement {
	return &FieldElement{
		V: [fieldLimbs]uint64{
			ct.Select(utils.BoolTo[uint64](choice), x0.V[0], x1.V[0]),
			ct.Select(utils.BoolTo[uint64](choice), x0.V[1], x1.V[1]),
		},
	}
}

// === Additive Group Methods.

func (*Field) Add(x *FieldElement, ys ...*FieldElement) *FieldElement {
	res := x.Clone()
	for _, y := range ys {
		res = res.Add(y)
	}
	return res
}

func (*Field) AdditiveIdentity() *FieldElement {
	return zero
}

func (*Field) Sub(x *FieldElement, ys ...*FieldElement) *FieldElement {
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
	return one
}

func (*Field) Div(x *FieldElement, ys ...*FieldElement) *FieldElement {
	res := x.Clone()
	for _, y := range ys {
		res = res.Div(y)
	}
	return res
}

// === Ring methods.

func (*Field) QuadraticResidue(p *FieldElement) (*FieldElement, error) {
	panic("not implemented")
}

func (*Field) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(2)
}
