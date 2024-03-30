package saferith_ex

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex/internal/boring"
)

type oddModulus struct {
	boringModulus *boring.BigNum
	montCtx       *boring.BigNumMontCtx
	modulus       *saferith.Modulus
}

func NewOddModulus(modulus *saferith.Nat) (Modulus, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	if modulus.Byte(0)&0b1 != 1 {
		return nil, errs.NewArgument("modulus is not odd")
	}

	m, err := boring.NewBigNum().SetBytes(modulus.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create modulus")
	}

	bnCtx := boring.NewBigNumCtx()
	montCtx, err := boring.NewBigNumMontCtx(m, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create modulus")
	}

	return &oddModulus{
		boringModulus: m,
		montCtx:       montCtx,
		modulus:       saferith.ModulusFromNat(modulus),
	}, nil
}

func (m *oddModulus) Modulus() *saferith.Modulus {
	return m.modulus
}

func (m *oddModulus) Nat() *saferith.Nat {
	return m.modulus.Nat()
}

func (m *oddModulus) Exp(base, exponent *saferith.Nat) (*saferith.Nat, error) {
	bnCtx := boring.NewBigNumCtx()

	b, err := boring.NewBigNum().SetBytes(base.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	bModM, err := boring.NewBigNum().Mod(b, m.boringModulus, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	e, err := boring.NewBigNum().SetBytes(exponent.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	r, err := boring.NewBigNum().Exp(bModM, e, m.boringModulus, m.montCtx, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	rBytes, err := r.Bytes()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	return new(saferith.Nat).SetBytes(rBytes), nil
}

func (m *oddModulus) MultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error) {
	bnCtx := boring.NewBigNumCtx()

	bb := make([]*boring.BigNum, len(bases))
	for i := range bases {
		bi, err := boring.NewBigNum().SetBytes(bases[i].Bytes())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		bb[i], err = boring.NewBigNum().Mod(bi, m.boringModulus, bnCtx)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
	}

	ee, err := boring.NewBigNum().SetBytes(exponent.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}
	rr := make([]*boring.BigNum, len(bb))

	jobFunc := func(i int) error {
		var err error
		localCtx := boring.NewBigNumCtx()
		rr[i], err = boring.NewBigNum().Exp(bb[i], ee, m.boringModulus, m.montCtx, localCtx)
		return err //nolint:wrapcheck // deliberate forward
	}

	var eg errgroup.Group
	for i := range bb {
		eg.Go(func() error { err := jobFunc(i); return err })
	}
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "error computing exp")
	}

	r := make([]*saferith.Nat, len(rr))
	for i := range rr {
		rriBytes, err := rr[i].Bytes()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}

		r[i] = new(saferith.Nat).SetBytes(rriBytes)
	}

	return r, nil
}

func (m *oddModulus) MultiExponentExp(base *saferith.Nat, exponents []*saferith.Nat) ([]*saferith.Nat, error) {
	bnCtx := boring.NewBigNumCtx()

	bb, err := boring.NewBigNum().SetBytes(base.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	bm, err := boring.NewBigNum().Mod(bb, m.boringModulus, bnCtx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create BigNum")
	}

	ee := make([]*boring.BigNum, len(exponents))
	for i := range exponents {
		ee[i], err = boring.NewBigNum().SetBytes(exponents[i].Bytes())
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
	}

	rr := make([]*boring.BigNum, len(ee))

	jobFunc := func(i int) error {
		localCtx := boring.NewBigNumCtx()
		rr[i], err = boring.NewBigNum().Exp(bm, ee[i], m.boringModulus, m.montCtx, localCtx)
		return err //nolint:wrapcheck // deliberate forward
	}

	var eg errgroup.Group
	for i := range ee {
		eg.Go(func() error { err := jobFunc(i); return err })
	}
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	r := make([]*saferith.Nat, len(rr))
	for i := range rr {
		rriBytes, err := rr[i].Bytes()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create BigNum")
		}
		r[i] = new(saferith.Nat).SetBytes(rriBytes)
	}

	return r, nil
}
