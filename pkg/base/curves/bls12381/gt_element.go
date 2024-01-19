package bls12381

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.GtMember = (*GtMember)(nil)
var _ encoding.BinaryMarshaler = (*GtMember)(nil)
var _ encoding.BinaryUnmarshaler = (*GtMember)(nil)
var _ json.Unmarshaler = (*GtMember)(nil)

type GtMember struct {
	V *bls12381impl.Gt

	_ types.Incomparable
}

func NewGtMember(input uint64) (curves.GtMember, error) {
	var data [bls12381impl.GtFieldBytes]byte
	data[7] = byte(input >> 56 & 0xFF)
	data[6] = byte(input >> 48 & 0xFF)
	data[5] = byte(input >> 40 & 0xFF)
	data[4] = byte(input >> 32 & 0xFF)
	data[3] = byte(input >> 24 & 0xFF)
	data[2] = byte(input >> 16 & 0xFF)
	data[1] = byte(input >> 8 & 0xFF)
	data[0] = byte(input & 0xFF)

	value, isCanonical := new(bls12381impl.Gt).SetBytes(&data)
	if isCanonical != 1 {
		return nil, errs.NewInvalidArgument("input is not canonical")
	}
	return &GtMember{V: value}, nil
}

// === Basic Methods.

func (g *GtMember) Equal(rhs curves.GtMember) bool {
	r, ok := rhs.(*GtMember)
	return ok && g.V.Equal(r.V) == 1
}

func (g *GtMember) Clone() curves.GtMember {
	return &GtMember{
		V: new(bls12381impl.Gt).Set(g.V),
	}
}

// === Groupoid Methods.

func (g *GtMember) Operate(rhs curves.GtMember) curves.GtMember {
	return g.Mul(rhs)
}

func (g *GtMember) OperateIteratively(x curves.GtMember, n *saferith.Nat) curves.GtMember {
	return g.ApplyMul(x, n)
}

func (g *GtMember) Order() *saferith.Modulus {
	if g.IsIdentity() {
		return saferith.ModulusFromUint64(0)
	}
	q := g.Clone()
	order := new(saferith.Nat).SetUint64(1)
	for !q.IsIdentity() {
		q = q.Operate(g)
		utils.IncrementNat(order)
	}
	return saferith.ModulusFromNat(order)
}

// === Multiplicative Groupoid Methods.

func (g *GtMember) Mul(rhs curves.GtMember) curves.GtMember {
	r, ok := rhs.(*GtMember)
	if ok {
		return &GtMember{
			V: new(bls12381impl.Gt).Add(g.V, r.V),
		}
	} else {
		panic("rhs is not in Gt")
	}
}

func (g *GtMember) ApplyMul(x curves.GtMember, n *saferith.Nat) curves.GtMember {
	reducedN := new(saferith.Nat).Mod(n, g.Gt().Order())
	if n.EqZero() == 1 {
		return g.Gt().MultiplicativeIdentity()
	}
	current := g.Clone()
	for reducedN.Eq(new(saferith.Nat).SetUint64(1)) != 1 {
		current = current.Mul(x)
		utils.DecrementNat(reducedN)
	}
	return current
}

func (g *GtMember) Square() curves.GtMember {
	return &GtMember{
		V: new(bls12381impl.Gt).Square(g.V),
	}
}

func (g *GtMember) Cube() curves.GtMember {
	value := new(bls12381impl.Gt).Square(g.V)
	value.Add(value, g.V)
	return &GtMember{
		V: value,
	}
}

// === Monoid Methods.

func (g *GtMember) IsIdentity() bool {
	return g.IsMultiplicativeIdentity()
}

// === Multiplicative Monoid Methods.

func (g *GtMember) IsMultiplicativeIdentity() bool {
	return g.V.IsOne() == 1
}

// === Group Methods.

func (g *GtMember) Inverse() curves.GtMember {
	return g.MultiplicativeInverse()
}

func (g *GtMember) IsInverse(of curves.GtMember) bool {
	return g.Operate(of).IsIdentity()
}

func (g *GtMember) IsTorsionElement(order *saferith.Modulus) bool {
	return g.ApplyMul(g, order.Nat()).IsIdentity()
}

// === Multiplicative Group Methods.

func (g *GtMember) MultiplicativeInverse() curves.GtMember {
	value, wasInverted := new(bls12381impl.Gt).Invert(g.V)
	if wasInverted != 1 {
		panic(errs.NewFailed("not invertible"))
	}
	return &GtMember{
		V: value,
	}
}

func (g *GtMember) IsMultiplicativeInverse(of curves.GtMember) bool {
	return g.Mul(of).IsMultiplicativeIdentity()
}

func (g *GtMember) Div(rhs curves.GtMember) curves.GtMember {
	r, ok := rhs.(*GtMember)
	if ok {
		return &GtMember{
			V: new(bls12381impl.Gt).Sub(g.V, r.V),
		}
	} else {
		panic("rhs is not in Gt")
	}
}

func (g *GtMember) ApplyDiv(x curves.GtMember, n *saferith.Nat) curves.GtMember {
	reducedN := new(saferith.Nat).Mod(n, g.Gt().Order())
	if n.EqZero() == 1 {
		return g.Gt().MultiplicativeIdentity()
	}
	current := g.Clone()
	for reducedN.Eq(new(saferith.Nat).SetUint64(1)) != 1 {
		current = current.Div(x)
		utils.DecrementNat(reducedN)
	}
	return current
}

// === Gt Methods.

func (*GtMember) Gt() curves.Gt {
	return NewGt()
}

// === Serialisation.

func (g *GtMember) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(g.Gt().Name(), g.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (g *GtMember) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(g.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != g.Gt().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	ss, ok := sc.(*GtMember)
	if !ok {
		return errs.NewInvalidType("invalid base field element")
	}
	g.V = ss.V
	return nil
}

func (g *GtMember) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(g.Gt().Name(), g.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (g *GtMember) UnmarshalJSON(input []byte) error {
	sc, err := impl.UnmarshalJson(g.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	name, _, err := impl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != g.Gt().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	S, ok := sc.(*GtMember)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	g.V = S.V
	return nil
}

func (g *GtMember) Bytes() []byte {
	bytes_ := g.V.Bytes()
	// should already be big endian
	return bytes_[:]
}

func (*GtMember) SetBytes(input []byte) (curves.GtMember, error) {
	var b [bls12381impl.GtFieldBytes]byte
	copy(b[:], input)
	ss, isCanonical := new(bls12381impl.Gt).SetBytes(&b)
	if isCanonical == 0 {
		return nil, errs.NewSerialisation("invalid bytes")
	}
	return &GtMember{V: ss}, nil
}

func (*GtMember) SetBytesWide(input []byte) (curves.GtMember, error) {
	if l := len(input); l != bls12381impl.GtFieldBytes*2 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	var b [bls12381impl.GtFieldBytes]byte
	copy(b[:], input[:bls12381impl.GtFieldBytes])

	value, isCanonical := new(bls12381impl.Gt).SetBytes(&b)
	if isCanonical == 0 {
		return nil, errs.NewSerialisation("invalid bytes")
	}
	copy(b[:], input[bls12381impl.GtFieldBytes:])
	value2, isCanonical := new(bls12381impl.Gt).SetBytes(&b)
	if isCanonical == 0 {
		return nil, errs.NewSerialisation("invalid bytes")
	}
	value.Add(value, value2)
	return &GtMember{V: value}, nil
}
