//go:build !purego && !nobignum

package modular

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
	"github.com/bronlabs/bron-crypto/pkg/cgo/boring"
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"
)

var (
	_ ResidueParams = (*oddResidueParamsBn)(nil)
)

type oddResidueParamsBn struct {
	saferithModulus *saferith.Modulus
	bnModulus       *boring.BigNum
	bnMontContext   *boring.BigNumMontCtx
}

func NewOddResidueParams(oddModulus *saferith.Nat) (ResidueParams, error) {
	if oddModulus == nil || oddModulus.EqZero() != 0 || !saferithUtils.NatIsOdd(oddModulus) {
		return nil, errs.NewArgument("invalid modulus")
	}

	bnMod, err := boring.NewBigNum().SetBytes(oddModulus.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set BigNum bytes")
	}

	bnCtx := boring.NewBigNumCtx()
	bnMontCtx, err := boring.NewBigNumMontCtx(bnMod, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNumMontCtx")
	}

	params := &oddResidueParamsBn{
		saferithModulus: saferith.ModulusFromNat(oddModulus),
		bnModulus:       bnMod,
		bnMontContext:   bnMontCtx,
	}

	return params, nil
}

func (p *oddResidueParamsBn) GetModulus() *saferith.Modulus {
	return p.saferithModulus
}

func (p *oddResidueParamsBn) ModExp(base, exponent *saferith.Nat) (*saferith.Nat, error) {
	bnBase, err := boring.NatToBigNum(new(saferith.Nat).Mod(base, p.saferithModulus))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create base BigNum")
	}

	bnExponent, err := boring.NatToBigNum(exponent)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create exponent BigNum")
	}

	bnCtx := boring.NewBigNumCtx()
	bnResult, err := boring.NewBigNum().Exp(bnBase, bnExponent, p.bnModulus, p.bnMontContext, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}
	result, err := boring.BigNumToNat(bnResult)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create result Nat")
	}

	return result.Resize(p.saferithModulus.BitLen()), nil
}

func (p *oddResidueParamsBn) ModMultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error) {
	var err error

	bnBases := make([]*boring.BigNum, len(bases))
	for i, base := range bases {
		bnBases[i], err = boring.NatToBigNum(new(saferith.Nat).Mod(base, p.saferithModulus))
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create base BigNum")
		}
	}

	bnExponent, err := boring.NatToBigNum(exponent)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create exponent BigNum")
	}

	bnResults := make([]*boring.BigNum, len(bnBases))
	var group errgroup.Group
	for i, bnBase := range bnBases {
		i := i
		group.Go(func() error {
			var err error
			bnCtx := boring.NewBigNumCtx()
			bnResults[i], err = boring.NewBigNum().Exp(bnBase, bnExponent, p.bnModulus, p.bnMontContext, bnCtx)
			return err
		})
	}
	err = group.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	results := make([]*saferith.Nat, len(bnResults))
	for i, bnResult := range bnResults {
		results[i], err = boring.BigNumToNat(bnResult)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create result Nat")
		}
	}

	return results, nil
}
