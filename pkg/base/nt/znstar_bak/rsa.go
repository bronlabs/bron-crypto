package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type RSAGroup UnitGroup

type RSAGroupKnownOrder interface {
	RSAGroup
	KnowledgeOfOrder[*modular.OddPrimeFactors, RSAGroup]
}

func NewRSAGroup(p, q *num.NatPlus) (RSAGroupKnownOrder, error) {
	if p == nil || q == nil {
		return nil, errs.NewValue("p and q must not be nil")
	}
	if p.AnnouncedLen() != q.AnnouncedLen() {
		return nil, errs.NewValue("p and q must have the same length")
	}
	if !p.IsProbablyPrime() {
		return nil, errs.NewValue("p must be prime")
	}
	if !q.IsProbablyPrime() {
		return nil, errs.NewValue("q must be prime")
	}
	zMod, err := num.NewZMod(p.Mul(q))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	arith, ok := modular.NewOddPrimeFactors(p.Value(), q.Value())
	if ok == ct.False {
		return nil, errs.NewValue("failed to create OddPrimeFactors")
	}
	return &rsaGroupKnownOrder{
		DenseUZMod: DenseUZMod[*modular.OddPrimeFactors]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

func NewRSAGroupOfUnknownOrder(m *num.NatPlus) (RSAGroup, error) {
	if m.AnnouncedLen() < 2048 {
		return nil, errs.NewValue("modulus must be at least 2048 bits")
	}
	zMod, err := num.NewZMod(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod")
	}
	arith, ok := modular.NewSimple(zMod.Modulus().ModulusCT())
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create SimpleModulus")
	}
	return &rsaGroup{
		DenseUZMod: DenseUZMod[*modular.SimpleModulus]{
			zMod:  zMod,
			arith: arith,
		},
	}, nil
}

type rsaGroup struct {
	DenseUZMod[*modular.SimpleModulus]
}

func (rg *rsaGroup) FromUint(input *num.Uint) (Unit, error) {
	u, err := rg.DenseUZMod.FromUint(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroup) FromNatCT(input *numct.Nat) (Unit, error) {
	u, err := rg.DenseUZMod.FromNatCT(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroup) One() Unit {
	u := rg.DenseUZMod.One()
	u.(*unit).g = rg
	return u
}

func (rg *rsaGroup) Random(prng io.Reader) (Unit, error) {
	u, err := rg.DenseUZMod.Random(prng)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroup) FromBytes(input []byte) (Unit, error) {
	u, err := rg.DenseUZMod.FromBytes(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroup) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	u, err := rg.DenseUZMod.FromCardinal(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroup) FromUint64(value uint64) (Unit, error) {
	u, err := rg.DenseUZMod.FromUint64(value)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

type rsaGroupKnownOrder struct {
	DenseUZMod[*modular.OddPrimeFactors]
}

func (rg *rsaGroupKnownOrder) Arithmetic() *modular.OddPrimeFactors {
	return rg.arith
}

func (rg *rsaGroupKnownOrder) FromUint(input *num.Uint) (Unit, error) {
	u, err := rg.DenseUZMod.FromUint(input)
	if err != nil {
		return nil, err
	}
	// Fix the group pointer to point to the wrapper
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroupKnownOrder) FromNatCT(input *numct.Nat) (Unit, error) {
	u, err := rg.DenseUZMod.FromNatCT(input)
	if err != nil {
		return nil, err
	}
	// Fix the group pointer to point to the wrapper
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroupKnownOrder) One() Unit {
	u := rg.DenseUZMod.One()
	u.(*unit).g = rg
	return u
}

func (rg *rsaGroupKnownOrder) Random(prng io.Reader) (Unit, error) {
	u, err := rg.DenseUZMod.Random(prng)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroupKnownOrder) FromBytes(input []byte) (Unit, error) {
	u, err := rg.DenseUZMod.FromBytes(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroupKnownOrder) FromCardinal(input cardinal.Cardinal) (Unit, error) {
	u, err := rg.DenseUZMod.FromCardinal(input)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroupKnownOrder) FromUint64(value uint64) (Unit, error) {
	u, err := rg.DenseUZMod.FromUint64(value)
	if err != nil {
		return nil, err
	}
	u.(*unit).g = rg
	return u, nil
}

func (rg *rsaGroupKnownOrder) ForgetOrder() RSAGroup {
	arith, ok := modular.NewSimple(rg.ModulusCT())
	if ok == ct.False {
		panic(errs.NewFailed("failed to create SimpleModulus"))
	}
	return &rsaGroup{
		DenseUZMod: DenseUZMod[*modular.SimpleModulus]{
			zMod:  rg.zMod,
			arith: arith,
		},
	}
}
