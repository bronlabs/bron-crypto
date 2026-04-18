package znstar

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	v     *num.Uint
	arith A
	n     *num.NatPlus
}

func (u *UnitTrait[A, W, WT]) Value() *num.Uint {
	return u.v
}

func (u *UnitTrait[A, W, WT]) Arithmetic() A {
	return u.arith
}

func (u *UnitTrait[A, W, WT]) set(v *num.Uint, arith A, n *num.NatPlus) {
	u.v = v
	u.arith = arith
	u.n = n
}

func (u *UnitTrait[A, W, WT]) IsUnknownOrder() bool {
	return u.arith.MultiplicativeOrder().IsUnknown()
}

func (u *UnitTrait[A, W, WT]) Modulus() *num.NatPlus {
	return u.v.Modulus()
}

func (u *UnitTrait[A, W, WT]) ModulusCT() *numct.Modulus {
	return u.arith.Modulus()
}

func (u *UnitTrait[A, W, WT]) EqualModulus(other W) bool {
	return u.Modulus().Equal(other.Modulus())
}

func (u *UnitTrait[A, W, WT]) Equal(other W) bool {
	return u.v.Equal(other.Value()) && u.EqualModulus(other)
}

func (u *UnitTrait[A, W, WT]) Op(other W) W {
	return u.Mul(other)
}

func (u *UnitTrait[A, W, WT]) mustBeValid(other W) {
	if !u.EqualModulus(other) {
		panic("cannot multiply units with different moduli")
	}
	if u.IsUnknownOrder() != other.IsUnknownOrder() {
		panic("cannot multiply units with different knowledge of order")
	}
}

func (u *UnitTrait[A, W, WT]) Mul(other W) W {
	u.mustBeValid(other)
	var outCt numct.Nat
	u.arith.ModMul(&outCt, u.v.Value(), other.Value().Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) Exp(exponent *num.Nat) W {
	var outCt numct.Nat
	u.arith.ModExp(&outCt, u.v.Value(), exponent.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) ExpBounded(exponent *num.Nat, bits uint) W {
	ex := exponent.Value().Clone()
	ex.Resize(int(bits))
	var outCt numct.Nat
	u.arith.ModExp(&outCt, u.v.Value(), ex)
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) ExpI(exponent *num.Int) W {
	var outCt numct.Nat
	u.arith.ModExpI(&outCt, u.v.Value(), exponent.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) ExpIBounded(exponent *num.Int, bits uint) W {
	ex := exponent.Value().Clone()
	ex.Resize(int(bits))
	var outCt numct.Nat
	u.arith.ModExpI(&outCt, u.v.Value(), ex)
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) Square() W {
	var outCt numct.Nat
	u.arith.ModMul(&outCt, u.v.Value(), u.v.Value())
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) TryInv() (W, error) {
	var outCt numct.Nat
	if ok := u.arith.ModInv(&outCt, u.v.Value()); ok == ct.False {
		return nil, ErrFailed.WithMessage("element is not invertible")
	}
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create unit")
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out), nil
}

func (u *UnitTrait[A, W, WT]) Inv() W {
	var outCt numct.Nat
	if ok := u.arith.ModInv(&outCt, u.v.Value()); ok == ct.False {
		panic(ErrFailed.WithMessage("element is not invertible"))
	}
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) TryOpInv() (W, error) {
	return u.TryInv()
}

func (u *UnitTrait[A, W, WT]) OpInv() W {
	return u.Inv()
}

func (u *UnitTrait[A, W, WT]) IsOpIdentity() bool {
	return u.IsOne()
}

func (u *UnitTrait[A, W, WT]) IsOne() bool {
	return u.v.IsOne()
}

func (u *UnitTrait[A, W, WT]) TryDiv(other W) (W, error) {
	u.mustBeValid(other)
	var outCt numct.Nat
	if ok := u.arith.ModDiv(&outCt, u.v.Value(), other.Value().Value()); ok == ct.False {
		return nil, ErrFailed.WithMessage("division failed: divisor not invertible")
	}
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create unit")
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out), nil
}

func (u *UnitTrait[A, W, WT]) Div(other W) W {
	u.mustBeValid(other)
	var outCt numct.Nat
	if ok := u.arith.ModDiv(&outCt, u.v.Value(), other.Value().Value()); ok == ct.False {
		panic(ErrFailed.WithMessage("division failed: divisor not invertible"))
	}
	v, err := num.NewUintGivenModulus(&outCt, u.ModulusCT())
	if err != nil {
		panic(err)
	}
	var out WT
	W(&out).set(v, u.arith, u.n)
	return W(&out)
}

func (u *UnitTrait[A, W, WT]) HashCode() base.HashCode {
	return u.v.HashCode().Combine(u.n.HashCode())
}

func (u *UnitTrait[A, W, WT]) Jacobi() (int, error) {
	out, err := nt.Jacobi(u.v.Lift(), u.n)
	if err != nil {
		return -2, errs.Wrap(err).WithMessage("failed to compute Jacobi symbol")
	}
	return out, nil
}

// IsTorsionFree reports whether the element lies in the torsion-free (odd-order)
// component of the unit group. For a CGGMP21-style ring over Z*_{N} or Z*_{N²}
// with N a safe-prime product, this coincides with the subgroup of quadratic
// residues; QR-mod-N² is equivalent to QR-mod-p AND QR-mod-q by Hensel's
// lemma, so the same Legendre-on-each-prime check decides both.
//
// The arithmetic type dictates how much we can actually decide:
//
//   - *modular.OddPrimeFactors and *modular.OddPrimeSquareFactors: the
//     factorisation is known, so QR membership is decided exactly by
//     computing the Legendre symbol modulo each prime factor of N.
//   - any other arithmetic (e.g. *modular.SimpleModulus): we fall back to
//     the Jacobi symbol modulo the primary modulus. This is a necessary
//     but not sufficient condition for QR membership; callers that need a
//     decision must accompany the element with a Πmod-style proof.
func (u *UnitTrait[A, W, WT]) IsTorsionFree() bool {
	pNat, qNat, haveFactors := u.primeFactors()
	if !haveFactors {
		j, err := u.Jacobi()
		return err == nil && j == 1
	}
	p, errP := num.NPlus().FromNatCT(pNat)
	q, errQ := num.NPlus().FromNatCT(qNat)
	if errP != nil || errQ != nil {
		return false
	}
	lifted := u.v.Lift()
	jp, err := nt.Jacobi(lifted, p)
	if err != nil || jp != 1 {
		return false
	}
	jq, err := nt.Jacobi(lifted, q)
	if err != nil || jq != 1 {
		return false
	}
	return true
}

// primeFactors returns the prime factors p, q of the primary modulus N when
// the arithmetic carries them (known-factorisation variants), or (nil, nil,
// false) otherwise. For OddPrimeSquareFactors the modulus is N² = (pq)²; we
// still return the primes of the primary modulus N, which is what QR checks
// via Jacobi need.
func (u *UnitTrait[A, W, WT]) primeFactors() (p, q *numct.Nat, ok bool) {
	switch a := any(u.arith).(type) {
	case *modular.OddPrimeFactors:
		return a.Params.PNat, a.Params.QNat, true
	case *modular.OddPrimeSquareFactors:
		return a.CrtModN.Params.PNat, a.CrtModN.Params.QNat, true
	default:
		return nil, nil, false
	}
}

func (u *UnitTrait[A, W, WT]) ScalarOp(scalar *num.Int) W {
	return u.ExpI(scalar)
}

func (u *UnitTrait[A, W, WT]) ScalarExp(scalar *num.Int) W {
	return u.ExpI(scalar)
}

func (u *UnitTrait[A, W, WT]) Cardinal() cardinal.Cardinal {
	return u.v.Cardinal()
}

func (u *UnitTrait[A, W, WT]) Bytes() []byte {
	return u.v.Bytes()
}

func (u *UnitTrait[A, W, WT]) String() string {
	return u.v.String()
}
