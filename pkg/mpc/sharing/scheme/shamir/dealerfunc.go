package shamir

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

type DealerFunc[FE algebra.PrimeFieldElement[FE]] struct {
	poly *polynomials.Polynomial[FE]
}

type dealerFuncDTO[FE algebra.PrimeFieldElement[FE]] struct {
	Poly *polynomials.Polynomial[FE] `json:"poly"`
}

func (a *DealerFunc[FE]) Basis() FE {
	return a.poly.Coefficients()[0]
}

// ShareOf evaluates the polynomial at the field element for the given ID,
// returning a Shamir share.
func (a *DealerFunc[FE]) ShareOf(id sharing.ID) *Share[FE] {
	field := algebra.StructureMustBeAs[algebra.PrimeField[FE]](a.poly.Ring().ScalarStructure())
	value := a.poly.Eval(SharingIDToLagrangeNode(field, id))
	share, _ := NewShare(id, value, nil)
	return share
}

// Repr yields the polynomial coefficients.
func (a *DealerFunc[FE]) Repr() iter.Seq[FE] {
	return func(yield func(FE) bool) {
		for _, c := range a.poly.Coefficients() {
			if !yield(c) {
				return
			}
		}
	}
}

// Accepts returns true if the polynomial is non-nil.
func (a *DealerFunc[FE]) Accepts(ac *accessstructures.Threshold) bool {
	return a.poly.Degree()+1 == int(ac.Threshold())
}

// Polynomial returns the underlying polynomial.
func (a *DealerFunc[FE]) Polynomial() *polynomials.Polynomial[FE] {
	return a.poly
}

func (a *DealerFunc[FE]) MarshalCBOR() ([]byte, error) {
	dto := dealerFuncDTO[FE]{
		Poly: a.poly,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dealer func")
	}
	return data, nil
}

func (a *DealerFunc[FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*dealerFuncDTO[FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Shamir Share")
	}
	if dto.Poly == nil {
		return sharing.ErrFailed.WithMessage("deserialised polynomial is nil")
	}
	if dto.Poly.Degree() < 1 {
		return sharing.ErrFailed.WithMessage("deserialised polynomial degree is less than 1")
	}
	a.poly = dto.Poly
	return nil
}

type LiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	poly *polynomials.ModuleValuedPolynomial[E, FE]
}

type liftedDealerFuncDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	Poly *polynomials.ModuleValuedPolynomial[E, FE] `json:"poly"`
}

func (a *LiftedDealerFunc[E, FE]) Basis() E {
	return a.poly.Coefficients()[0]
}

func (a *LiftedDealerFunc[E, FE]) ShareOf(id sharing.ID) *LiftedShare[E, FE] {
	field := algebra.StructureMustBeAs[algebra.PrimeField[FE]](a.poly.ScalarStructure())
	point := field.FromUint64(uint64(id))
	value := a.poly.Eval(point)
	return &LiftedShare[E, FE]{id: id, v: value}
}

func (a *LiftedDealerFunc[E, FE]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, c := range a.poly.Coefficients() {
			if !yield(c) {
				return
			}
		}
	}
}

func (a *LiftedDealerFunc[E, FE]) Accepts(ac *accessstructures.Threshold) bool {
	return a.poly.Degree()+1 == int(ac.Threshold())
}

// Op returns a new LiftedDealerFunc that is the coefficient-wise sum of two
// lifted polynomials. This is used by the meta Pedersen VSS scheme to combine
// the share and blinding verification vectors.
func (a *LiftedDealerFunc[E, FE]) Op(other *LiftedDealerFunc[E, FE]) *LiftedDealerFunc[E, FE] {
	return &LiftedDealerFunc[E, FE]{poly: a.poly.Op(other.poly)}
}

func (a *LiftedDealerFunc[E, FE]) Polynomial() *polynomials.ModuleValuedPolynomial[E, FE] {
	return a.poly
}

func (a *LiftedDealerFunc[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := liftedDealerFuncDTO[E, FE]{
		Poly: a.poly,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal lifted dealer func")
	}
	return data, nil
}

func (a *LiftedDealerFunc[E, FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*liftedDealerFuncDTO[E, FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal lifted dealer func")
	}
	if dto.Poly == nil {
		return sharing.ErrFailed.WithMessage("deserialised lifted polynomial is nil")
	}
	if dto.Poly.Degree() < 1 {
		return sharing.ErrFailed.WithMessage("deserialised lifted polynomial degree is less than 1")
	}
	a.poly = dto.Poly
	return nil
}
