package saferith_ex

import (
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type genericModulus struct {
	modulus *saferith.Modulus
}

func NewGenericModulus(modulus *saferith.Nat) (Modulus, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}

	return &genericModulus{
		modulus: saferith.ModulusFromNat(modulus),
	}, nil
}

func (m *genericModulus) Modulus() *saferith.Modulus {
	return m.modulus
}

func (m *genericModulus) Nat() *saferith.Nat {
	return m.modulus.Nat()
}

func (m *genericModulus) Exp(base, exponent *saferith.Nat) (*saferith.Nat, error) {
	return new(saferith.Nat).Exp(base, exponent, m.modulus), nil
}

func (m *genericModulus) MultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error) {
	results := make([]*saferith.Nat, len(bases))

	var wg sync.WaitGroup
	job := func(i int) {
		results[i] = new(saferith.Nat).Exp(bases[i], exponent, m.modulus)
		wg.Done()
	}

	wg.Add(len(bases))
	for i := range bases {
		go job(i)
	}
	wg.Wait()

	return results, nil
}

func (m *genericModulus) MultiExponentExp(base *saferith.Nat, exponents []*saferith.Nat) ([]*saferith.Nat, error) {
	results := make([]*saferith.Nat, len(exponents))

	var wg sync.WaitGroup
	job := func(i int) {
		results[i] = new(saferith.Nat).Exp(base, exponents[i], m.modulus)
		wg.Done()
	}

	wg.Add(len(exponents))
	for i := range exponents {
		go job(i)
	}
	wg.Wait()

	return results, nil
}
