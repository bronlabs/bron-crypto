//go:build !purego && !nobignum

package modular

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/cgo/boring"
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"
)

func FastExp(b, e *saferith.Nat, m *saferith.Modulus) (*saferith.Nat, error) {
	bReduced := new(saferith.Nat).Mod(b, m)
	bBytes := bReduced.Bytes()
	eBytes := e.Bytes()
	mBytes := m.Bytes()

	bNum, err := boring.NewBigNum().SetBytes(bBytes)
	if err != nil {
		return nil, err
	}
	eNum, err := boring.NewBigNum().SetBytes(eBytes)
	if err != nil {
		return nil, err
	}
	mNum, err := boring.NewBigNum().SetBytes(mBytes)
	if err != nil {
		return nil, err
	}

	bnCtx := boring.NewBigNumCtx()
	montCtx, err := boring.NewBigNumMontCtx(mNum, bnCtx)
	if err != nil {
		return nil, err
	}
	rNum, err := boring.NewBigNum().Exp(bNum, eNum, mNum, montCtx, bnCtx)
	if err != nil {
		return nil, err
	}
	rBytes, err := rNum.Bytes()
	if err != nil {
		return nil, err
	}

	return new(saferith.Nat).SetBytes(rBytes), nil
}

func FastMultiBaseExp(bs []*saferith.Nat, e *saferith.Nat, m *saferith.Modulus) ([]*saferith.Nat, error) {
	bsNum := make([]*boring.BigNum, len(bs))
	for i, b := range bs {
		var err error
		bReduced := new(saferith.Nat).Mod(b, m)
		bBytes := bReduced.Bytes()
		bsNum[i], err = boring.NewBigNum().SetBytes(bBytes)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create big num")
		}
	}
	eBytes := e.Bytes()
	eNum, err := boring.NewBigNum().SetBytes(eBytes)
	if err != nil {
		return nil, err
	}
	mBytes := m.Bytes()
	mNum, err := boring.NewBigNum().SetBytes(mBytes)
	if err != nil {
		return nil, err
	}

	bnCtx := boring.NewBigNumCtx()
	montCtx, err := boring.NewBigNumMontCtx(mNum, bnCtx)
	if err != nil {
		return nil, err
	}

	rs := make([]*saferith.Nat, len(bs))
	var eg errgroup.Group
	for i, bNum := range bsNum {
		eg.Go(func() error {
			var err error
			ctx := boring.NewBigNumCtx()
			rNum, err := boring.NewBigNum().Exp(bNum, eNum, mNum, montCtx, ctx)
			if err != nil {
				return err
			}
			rBytes, err := rNum.Bytes()
			if err != nil {
				return err
			}

			rs[i] = new(saferith.Nat).SetBytes(rBytes)
			return nil
		})
	}
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute powers")
	}

	return rs, nil
}
