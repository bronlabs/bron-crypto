package bls12381

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
)

const NameGt = "BLS12381Gt"

var (
	gtInitonce sync.Once
	gtInstance Gt

	p12 = new(saferith.Nat).Mul(p.Nat(), embeddingDegree, p.Nat().AnnouncedLen()+embeddingDegree.AnnouncedLen())
)

var _ curves.Gt = (*Gt)(nil)

type Gt struct {
	hashing.CurveHasher

	_ types.Incomparable
}

func gtInit() {
	gtInstance = Gt{}
}

func NewGt() *Gt {
	gtInitonce.Do(gtInit)
	return &gtInstance
}

// === Basic Methods.

func (*Gt) Name() string {
	return NameGt
}

func (*Gt) Order() *saferith.Modulus {
	return saferith.ModulusFromNat(p12)
}

func (g *Gt) Element() curves.GtMember {
	return g.Identity()
}

func (g *Gt) OperateOver(operator algebra.Operator, ps ...curves.GtMember) (curves.GtMember, error) {
	if operator != algebra.Multiplication {
		return nil, errs.NewInvalidType("operator %v is not supported", operator)
	}
	current := g.Identity()
	for _, p := range ps {
		current = current.Operate(p)
	}
	return current, nil
}

func (*Gt) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Multiplication}
}

func (*Gt) Random(prng io.Reader) (curves.GtMember, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	value, err := new(bls12381impl.Gt).Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar in BLS12381Gt")
	}
	return &GtMember{V: value}, nil
}

func (g *Gt) Hash(x []byte) (curves.GtMember, error) {
	reader := sha3.NewShake256()
	_, err := reader.Write(x)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not write inputs to hash")
	}
	return g.Random(reader)
}

// === Multiplicative Groupoid Methods.

func (*Gt) Multiply(x curves.GtMember, ys ...curves.GtMember) curves.GtMember {
	product := x
	for _, y := range ys {
		product = product.Mul(y)
	}
	return product
}

// === Monoid Methods.

func (*Gt) Identity() curves.GtMember {
	return &GtMember{V: new(bls12381impl.Gt).SetOne()}
}

// === Multiplicative Monoid Methods.

func (g *Gt) MultiplicativeIdentity() curves.GtMember {
	return g.Identity()
}

// === Multiplicative Group Methods.

func (*Gt) Div(x curves.GtMember, ys ...curves.GtMember) curves.GtMember {
	result := x
	for _, y := range ys {
		result = result.Div(y)
	}
	return result
}
