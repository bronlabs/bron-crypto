package bls12381

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

const NameGt = "BLS12381Gt"

var (
	gtInitonce sync.Once
	gtInstance Gt

	p12 = new(saferith.Nat).Mul(p.Nat(), embeddingDegree, p.Nat().AnnouncedLen()+embeddingDegree.AnnouncedLen())
)

var _ curves.Gt = (*Gt)(nil)

type Gt struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func gtInit() {
	gtInstance = Gt{}
}

func NewGt() *Gt {
	gtInitonce.Do(gtInit)
	return &gtInstance
}

func (*Gt) GetOperator(name algebra.Operator) (algebra.BinaryOperator[curves.GtMember], bool) {
	//TODO implement me
	panic("implement me")
}

// === Basic Methods.

func (*Gt) Cardinality() *saferith.Modulus {
	panic("not implemented")
}

func (*Gt) Contains(e curves.GtMember) bool {
	panic("not implemented")
}

func (*Gt) Iter() <-chan curves.GtMember {
	panic("not implemented")
}

func (g *Gt) Unwrap() curves.Gt {
	return g
}

func (*Gt) IsDefinedUnder(operator algebra.Operator) bool {
	panic("not implemented")
}

func (*Gt) Operate(operator algebra.Operator, x algebra.GroupoidElement[curves.Gt, curves.GtMember], ys ...algebra.GroupoidElement[curves.Gt, curves.GtMember]) (curves.GtMember, error) {
	panic("not implemented")
}

func (*Gt) Exp(base curves.GtMember, power curves.GtMember) curves.GtMember {
	panic("not implemented")
}

func (*Gt) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.Gt, curves.GtMember], exponents []*saferith.Nat) (curves.GtMember, error) {
	panic("not implemented")
}

func (*Gt) Operators() []algebra.Operator {
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
	return saferith.ModulusFromNat(p12)
}

func (g *Gt) Element() curves.GtMember {
	return g.MultiplicativeIdentity()
}

func (*Gt) Random(prng io.Reader) (curves.GtMember, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	value, err := new(bls12381impl.Gt).Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random scalar in BLS12381Gt")
	}
	return &GtMember{V: value}, nil
}

func (g *Gt) Hash(x []byte) (curves.GtMember, error) {
	reader := sha3.NewShake256()
	_, err := reader.Write(x)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not write inputs to hash")
	}
	return g.Random(reader)
}

func (g *Gt) Select(choice bool, x0, x1 curves.GtMember) curves.GtMember {
	x0Gt, ok0 := x0.(*GtMember)
	x1Gt, ok1 := x1.(*GtMember)
	sGt, oks := g.Element().(*GtMember)
	if !ok0 || !ok1 || oks {
		panic("Not a BLS12381 Gt element")
	}
	sGt.V.A.CMove(&x0Gt.V.A, &x1Gt.V.A, utils.BoolTo[int](choice))
	sGt.V.B.CMove(&x0Gt.V.B, &x1Gt.V.B, utils.BoolTo[int](choice))
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

func (*Gt) Identity(under algebra.Operator) (curves.GtMember, error) {
	panic("not implemented")
}

// === Multiplicative Monoid Methods.

func (*Gt) MultiplicativeIdentity() curves.GtMember {
	return &GtMember{V: new(bls12381impl.Gt).SetOne()}
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
