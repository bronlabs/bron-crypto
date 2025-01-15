package bls12381

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

var _ curves.GtMember = (*GtMember)(nil)
var _ encoding.BinaryMarshaler = (*GtMember)(nil)
var _ encoding.BinaryUnmarshaler = (*GtMember)(nil)
var _ json.Unmarshaler = (*GtMember)(nil)

type GtMember struct {
	V *bls12381impl.Gt

	_ ds.Incomparable
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
		return nil, errs.NewArgument("input is not canonical")
	}
	return &GtMember{V: value}, nil
}

// === Basic Methods.

func (*GtMember) Structure() curves.Gt {
	panic("implement me")
}

func (*GtMember) Unwrap() curves.GtMember {
	panic("implement me")
}

func (*GtMember) ApplyOp(operator algebra.BinaryOperator[curves.GtMember], x algebra.GroupoidElement[curves.Gt, curves.GtMember], n *saferith.Nat) (curves.GtMember, error) {
	panic("implement me")
}

func (*GtMember) Exp(exponent *saferith.Nat) curves.GtMember {
	panic("implement me")
}

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

func (g *GtMember) OperateIteratively(n *saferith.Nat) curves.GtMember {
	return g.Gt().MultiplicativeIdentity().ApplyMul(g, n)
}

func (*GtMember) Order(operator algebra.BinaryOperator[curves.GtMember]) (*saferith.Modulus, error) {
	panic("implement me")

	//if g.IsIdentity() {
	//	return saferith.ModulusFromUint64(0)
	//}
	//q := g.Clone()
	//order := saferithUtils.NatOne
	//for !q.IsIdentity() {
	//	q = q.Operate(g)
	//	saferithUtils.NatInc(order)
	//}
	//return saferith.ModulusFromNat(order)
}

// === Multiplicative Groupoid Methods.

func (g *GtMember) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember]) curves.GtMember {
	r, ok := rhs.(*GtMember)
	if ok {
		return &GtMember{
			V: new(bls12381impl.Gt).Add(g.V, r.V),
		}
	} else {
		panic("rhs is not in Gt")
	}
}

func (g *GtMember) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember], n *saferith.Nat) curves.GtMember {
	reducedN := new(saferith.Nat).Mod(n, g.Gt().Order())
	if n.EqZero() == 1 {
		return g.Gt().MultiplicativeIdentity()
	}
	current := g.Clone()
	for reducedN.Eq(saferithUtils.NatOne) != 1 {
		current = current.Mul(x)
		saferithUtils.NatDec(reducedN)
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

func (*GtMember) IsIdentity(under algebra.BinaryOperator[curves.GtMember]) (bool, error) {
	panic("implement me")
}

// === Multiplicative Monoid Methods.

func (g *GtMember) IsMultiplicativeIdentity() bool {
	return g.V.IsOne() == 1
}

// === Group Methods.

func (*GtMember) Inverse(under algebra.BinaryOperator[curves.GtMember]) (curves.GtMember, error) {
	panic("implement me")
}

func (*GtMember) IsInverse(of algebra.GroupElement[curves.Gt, curves.GtMember], under algebra.BinaryOperator[curves.GtMember]) (bool, error) {
	panic("implement me")
}

func (*GtMember) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.GtMember]) (bool, error) {
	panic("implement me")
}

func (g *GtMember) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	return g.ApplyMul(g, order.Nat()).IsMultiplicativeIdentity()
}

// === Multiplicative Group Methods.

func (g *GtMember) MultiplicativeInverse() (curves.GtMember, error) {
	value, wasInverted := new(bls12381impl.Gt).Invert(g.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("not invertible")
	}

	return &GtMember{
		V: value,
	}, nil
}

func (g *GtMember) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.Gt, curves.GtMember]) bool {
	return g.Mul(of).IsMultiplicativeIdentity()
}

func (g *GtMember) Div(rhs algebra.MultiplicativeGroupElement[curves.Gt, curves.GtMember]) (curves.GtMember, error) {
	r, ok := rhs.(*GtMember)
	if ok {
		return &GtMember{
			V: new(bls12381impl.Gt).Sub(g.V, r.V),
		}, nil
	} else {
		panic("rhs is not in Gt")
	}
}

func (g *GtMember) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.Gt, curves.GtMember], n *saferith.Nat) (curves.GtMember, error) {
	reducedN := new(saferith.Nat).Mod(n, g.Gt().Order())
	if n.EqZero() == 1 {
		return g.Gt().MultiplicativeIdentity(), nil
	}
	current := g.Clone()
	for reducedN.Eq(saferithUtils.NatOne) != 1 {
		var err error
		current, err = current.Div(x)
		if err != nil {
			return nil, errs.WrapFailed(err, "division failed")
		}
		saferithUtils.NatDec(reducedN)
	}

	return current, nil
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
		return errs.NewType("name %s is not supported", name)
	}
	ss, ok := sc.(*GtMember)
	if !ok {
		return errs.NewType("invalid base field element")
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
	sc, err := impl.UnmarshalJson(g.Gt().Name(), g.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
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
		return nil, errs.NewLength("invalid byte sequence")
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

func (g *GtMember) HashCode() uint64 {
	return binary.BigEndian.Uint64(g.Bytes())
}
