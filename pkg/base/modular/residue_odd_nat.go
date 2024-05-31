//go:build purego || nobignum

package modular

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	_ ResidueParams = (*oddResidueParamsNat)(nil)
)

type oddResidueParamsNat struct {
	saferithModulus *saferith.Modulus
}

func NewOddResidueParams(oddModulus *saferith.Nat) (ResidueParams, error) {
	if oddModulus == nil || oddModulus.EqZero() != 0 || !saferithUtils.NatIsOdd(oddModulus) {
		return nil, errs.NewArgument("invalid modulus")
	}

	params := &oddResidueParamsNat{
		saferithModulus: saferith.ModulusFromNat(oddModulus),
	}

	return params, nil
}

func (p *oddResidueParamsNat) GetModulus() *saferith.Modulus {
	return p.saferithModulus
}

func (p *oddResidueParamsNat) ModExp(base, exponent *saferith.Nat) (*saferith.Nat, error) {
	return new(saferith.Nat).Exp(base, exponent, p.saferithModulus), nil
}

func (p *oddResidueParamsNat) ModMultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error) {
	results := make([]*saferith.Nat, len(bases))

	var errGroup errgroup.Group
	for i := range bases {
		errGroup.Go(func() error {
			results[i] = new(saferith.Nat).Exp(bases[i], exponent, p.saferithModulus)
			return nil
		})
	}
	_ = errGroup.Wait()

	return results, nil
}
