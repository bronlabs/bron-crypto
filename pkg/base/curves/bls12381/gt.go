package bls12381

import (
	"io"
	"iter"
	"sync"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

const NameGt = "BLS12381Gt"

var (
	gtInitOnce sync.Once
	gtInstance Gt

	gtOrder = new(saferith.Nat).Mul(g1BaseFieldOrder.Nat(), embeddingDegree, -1)
)

var _ curves.Gt = (*Gt)(nil)

type Gt struct {
	_ ds.Incomparable
}

func gtInit() {
	gtInstance = Gt{}
}

func NewGt() *Gt {
	gtInitOnce.Do(gtInit)
	return &gtInstance
}

// === Basic Methods.

func (*Gt) Cardinality() *saferith.Nat {
	panic("not implemented")
}

func (*Gt) Contains(e curves.GtMember) bool {
	panic("not implemented")
}

func (*Gt) Iter() iter.Seq[curves.GtMember] {
	panic("not implemented")
}

func (g *Gt) Unwrap() curves.Gt {
	return g
}

func (*Gt) IsDefinedUnder(operator algebra.BinaryOperator[curves.GtMember]) bool {
	panic("not implemented")
}

func (*Gt) Op(operator algebra.BinaryOperator[curves.GtMember], x algebra.GroupoidElement[curves.Gt, curves.GtMember], ys ...algebra.GroupoidElement[curves.Gt, curves.GtMember]) (curves.GtMember, error) {
	panic("not implemented")
}

func (*Gt) Exp(base curves.GtMember, power curves.GtMember) curves.GtMember {
	panic("not implemented")
}

func (*Gt) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember], exponents []*saferith.Nat) (curves.GtMember, error) {
	panic("not implemented")
}

func (*Gt) Operators() []algebra.BinaryOperator[curves.GtMember] {
	panic("not implemented")
}

func (*Gt) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember], exponent *saferith.Nat) curves.GtMember {
	panic("not implemented")
}

func (*Gt) MultiExponentExp(base algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember], exponents []*saferith.Nat) curves.GtMember {
	panic("not implemented")
}

func (*Gt) Multiplication() algebra.Multiplication[curves.GtMember] {
	panic("not implemented")
}

func (*Gt) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.GtMember] {
	panic("not implemented")
}

func (*Gt) Name() string {
	return NameGt
}

func (*Gt) Order() *saferith.Modulus {
	return saferith.ModulusFromNat(gtOrder)
}

func (g *Gt) Element() curves.GtMember {
	return g.MultiplicativeIdentity()
}

func (*Gt) Random(prng io.Reader) (curves.GtMember, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	value := new(GtMember)
	ok := value.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("could not generate random scalar in BLS12381Gt")
	}
	return value, nil
}

func (g *Gt) Hash(x []byte) (curves.GtMember, error) {
	reader := sha3.NewShake256()
	_, err := reader.Write(x)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not write inputs to hash")
	}
	return g.Random(reader)
}

func (*Gt) Select(choice uint64, x0, x1 curves.GtMember) curves.GtMember {
	x0Gt, ok0 := x0.(*GtMember)
	if !ok0 {
		panic("x0 is not a non-empty BLS12381 Gt element")
	}
	x1Gt, ok1 := x1.(*GtMember)
	if !ok1 {
		panic("x1 is not a non-empty BLS12381 Gt element")
	}
	sGt := new(GtMember)
	sGt.V.Select(choice, &x0Gt.V.Fp12, &x1Gt.V.Fp12)
	return sGt
}

// === Multiplicative Groupoid Methods.

func (*Gt) Mul(x algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember], ys ...algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember]) curves.GtMember {
	product := x
	for _, y := range ys {
		product = product.Mul(y)
	}
	return product.Unwrap()
}

// === Monoid Methods.

func (*Gt) Identity(under algebra.BinaryOperator[curves.GtMember]) (curves.GtMember, error) {
	panic("not implemented")
}

// === Multiplicative Monoid Methods.

func (*Gt) MultiplicativeIdentity() curves.GtMember {
	result := new(GtMember)
	result.V.SetOne()
	return result
}

// === Multiplicative Group Methods.

func (*Gt) Div(x algebra.MultiplicativeGroupElement[curves.Gt, curves.GtMember], ys ...algebra.MultiplicativeGroupElement[curves.Gt, curves.GtMember]) (curves.GtMember, error) {
	result := x
	for _, y := range ys {
		var err error
		result, err = result.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "division failed")
		}
	}
	return result.Unwrap(), nil
}
