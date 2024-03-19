package bf256

import (
	"encoding/binary"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
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

var _ algebra.AbstractFiniteField[*Field, *FieldElement] = (*Field)(nil)

type Field struct{}

func NewField() *Field {
	return field2e256Instance
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
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (*Field) OperateOver(operator algebra.Operator, xs ...*FieldElement) (*FieldElement, error) {
	panic("not implemented")
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

func (*Field) Select(choice int, x0, x1 *FieldElement) *FieldElement {
	el := x0.Clone()
	el.V[0] = ct.Select(uint64(choice), el.V[0], x1.V[0])
	el.V[1] = ct.Select(uint64(choice), el.V[1], x1.V[1])
	el.V[2] = ct.Select(uint64(choice), el.V[2], x1.V[2])
	el.V[3] = ct.Select(uint64(choice), el.V[3], x1.V[3])
	return el
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
	return &FieldElement{}
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
	return &FieldElement{
		V: [fieldLimbsF2e256]uint64{1, 0, 0, 0},
	}
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
