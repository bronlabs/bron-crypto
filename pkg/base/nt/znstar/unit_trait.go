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

// UnitTrait is the shared implementation of a unit-group element. It stores
// the integer representative v ∈ [0, N), the arithmetic backend inherited
// from the group (which encodes whether the trapdoor view is active), and
// the primary modulus n (for Paillier: the square root of the ambient
// modulus). Every concrete element type in this package — RSA and Paillier,
// known- and unknown-order — embeds this trait and promotes its methods.
type UnitTrait[A modular.Arithmetic, W unitWrapperPtrConstraint[A, WT], WT any] struct {
	v     *num.Uint
	arith A
	n     *num.NatPlus
}

// Value returns the underlying integer representative of the element. The
// returned pointer aliases internal state; callers must clone before
// mutating if aliasing is unwanted.
func (u *UnitTrait[A, W, WT]) Value() *num.Uint {
	return u.v
}

// Arithmetic returns the modular-arithmetic backend carried by the element.
// Concrete callers can type-switch on the returned value to recover
// trapdoor material when the element is held under the known-order view.
func (u *UnitTrait[A, W, WT]) Arithmetic() A {
	return u.arith
}

// set is the internal constructor used by the generic machinery to
// initialise an embedded UnitTrait from (value, arithmetic, primary
// modulus). It is deliberately unexported; callers must go through the
// typed group constructors (FromUint, FromBytes, …) so that the unit
// (coprime-with-N) invariant is enforced.
func (u *UnitTrait[A, W, WT]) set(v *num.Uint, arith A, n *num.NatPlus) {
	u.v = v
	u.arith = arith
	u.n = n
}

// IsUnknownOrder reports whether the element is held under the trapdoor-
// free view. Use this to branch between fast CRT-backed paths and generic
// fallbacks in code that is generic over both views.
func (u *UnitTrait[A, W, WT]) IsUnknownOrder() bool {
	return u.arith.MultiplicativeOrder().IsUnknown()
}

// Modulus returns the ambient modulus (Z/NZ) that this element is reduced
// modulo. For Paillier elements this is N² rather than N.
func (u *UnitTrait[A, W, WT]) Modulus() *num.NatPlus {
	return u.v.Modulus()
}

// ModulusCT returns the constant-time modulus handle attached to the
// element's arithmetic. Prefer this over Modulus().ModulusCT() on hot
// paths; it avoids an allocation.
func (u *UnitTrait[A, W, WT]) ModulusCT() *numct.Modulus {
	return u.arith.Modulus()
}

// EqualModulus reports whether the two elements share the same ambient
// modulus. It is the precondition for binary operations — multiplying
// elements from different groups is meaningless, so callers rely on this
// (or the Equal-style wrappers that use it) before combining values.
func (u *UnitTrait[A, W, WT]) EqualModulus(other W) bool {
	return u.Modulus().Equal(other.Modulus())
}

// Equal reports whether the two elements are equal as values in the same
// group: same modulus and same representative integer. It does NOT attempt
// to match elements across groups with the same modulus but different
// known-order status; that distinction is carried at the type level.
func (u *UnitTrait[A, W, WT]) Equal(other W) bool {
	return u.v.Equal(other.Value()) && u.EqualModulus(other)
}

// Op is the group operation, exposed under the generic algebra interface
// name; for unit groups it is multiplication.
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

// Mul returns u · other in the group. Both operands must belong to the
// same ambient modulus and the same known-order view; mismatches panic
// rather than silently returning a nonsense value, because mixing views
// is almost always a programming error with security consequences.
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

// Exp returns u^exponent. The backing ModExp is constant-time in the
// exponent bit width; callers whose exponent has a tight bit bound
// smaller than the underlying word storage should prefer ExpBounded to
// avoid leaking an upper bound on the exponent via timing. Behaviour
// under the known-order view is CRT-accelerated; otherwise a generic
// Montgomery-ladder-style ModExp is used.
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

// ExpBounded returns u^exponent after truncating the exponent to the
// supplied bit width. Use this when the exponent is sampled from a
// bounded range — e.g. the CGGMP21 Schnorr-style challenges of length
// l+ε — to keep the modular-exponentiation cost proportional to the
// actual bit length of the secret, and to avoid timing leakage of
// higher-order zero bits.
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

// ExpI is the signed-exponent variant of Exp: negative exponents invert
// u first (so u^{-k} = (u^{-1})^k). The underlying arithmetic keeps the
// operation constant-time with respect to the absolute value of the
// exponent. Used wherever a ZK prover raises a base to a response z = α + e·x
// that may be negative (e.g. in range proofs).
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

// ExpIBounded is the signed, bit-bounded variant of Exp. It truncates
// the exponent to the given number of bits (of its absolute value)
// before exponentiating — useful for responses in range proofs where
// the exponent's magnitude is cryptographically bounded by the proof's
// soundness parameters.
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

// Square returns u² — the image of u under the squaring map. Squaring
// is the canonical projection (Z/NZ)* ↠ QR_N; every quadratic residue
// has 4 preimages when N is a product of two odd primes. Cryptographic
// applications use Square both as a cheap specialisation of Mul and as
// the first step of projecting into QR_N.
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

// TryInv returns the multiplicative inverse u^{-1}, or an error if u is
// not invertible. Since every element constructed via the group
// constructors is already verified to be a unit, the error path here is
// reserved for inputs that slipped past those checks (e.g. values built
// by direct struct manipulation).
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

// Inv is the panicking variant of TryInv. It is safe to use whenever u
// originates from a group constructor (which guarantees the unit
// property) and is preferred in hot paths to avoid the allocation of an
// error value.
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

// TryOpInv is the group-operation inverse — the inverse of Op — exposed
// under the generic algebra interface name. For unit groups it coincides
// with TryInv.
func (u *UnitTrait[A, W, WT]) TryOpInv() (W, error) {
	return u.TryInv()
}

// OpInv is the panicking group-operation inverse. Coincides with Inv for
// unit groups.
func (u *UnitTrait[A, W, WT]) OpInv() W {
	return u.Inv()
}

// IsOpIdentity reports whether u is the identity under the group
// operation. For unit groups this is the identity 1.
func (u *UnitTrait[A, W, WT]) IsOpIdentity() bool {
	return u.IsOne()
}

// IsOne reports whether u equals 1 in the ambient ring — the multiplicative
// identity of the group. Equivalent to checking that u has order 1.
func (u *UnitTrait[A, W, WT]) IsOne() bool {
	return u.v.IsOne()
}

// TryDiv returns u · other^{-1}, or an error if other is not invertible.
// The panicking variant Div is preferred when both operands come from
// the same group's constructors.
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

// Div returns u · other^{-1}; panics if other is not invertible. Safe to
// use on elements obtained from the group constructors.
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

// HashCode returns a non-cryptographic hash of the element, suitable for
// map keys and deduplication. The hash mixes in the primary modulus so
// that two elements with the same numeric value but drawn from different
// groups do not collide.
func (u *UnitTrait[A, W, WT]) HashCode() base.HashCode {
	return u.v.HashCode().Combine(u.n.HashCode())
}

// Jacobi returns the Jacobi symbol (u / N) ∈ {-1, 0, +1} computed against
// the primary modulus N. For odd N, the symbol is +1 for every element
// of QR_N and also for non-residues that happen to be residues modulo
// each prime factor on an even number of them — so Jacobi == 1 is a
// necessary but not sufficient QR witness over a composite modulus.
// Returns -2 only on internal failures inside the underlying big-int
// Jacobi routine.
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

// ScalarOp is the Z-module scalar action: u ↦ u^scalar. For unit groups
// this coincides with integer exponentiation; it is exposed under the
// generic module-action interface name so that algorithms written against
// the abstract Z-module interface can operate uniformly on unit groups
// and on elliptic-curve groups.
func (u *UnitTrait[A, W, WT]) ScalarOp(scalar *num.Int) W {
	return u.ExpI(scalar)
}

// ScalarExp is an alias for ScalarOp exposed under the exponentiation
// interface name, for algorithms that treat the operation as "raising to
// a scalar" rather than "applying a module action".
func (u *UnitTrait[A, W, WT]) ScalarExp(scalar *num.Int) W {
	return u.ExpI(scalar)
}

// Cardinal returns the element's integer representative as a Cardinal.
// Cardinals are unbounded, so this is lossless and suitable for passing
// the value into routines that need to treat it as a plain integer
// rather than as a modular residue.
func (u *UnitTrait[A, W, WT]) Cardinal() cardinal.Cardinal {
	return u.v.Cardinal()
}

// Bytes returns the canonical big-endian fixed-length byte encoding of
// the element. The length is ElementSize() of the parent group, so two
// encodings of elements in the same group are directly comparable.
// Callers that need a variable-length minimal encoding should trim
// leading zero bytes themselves.
func (u *UnitTrait[A, W, WT]) Bytes() []byte {
	return u.v.Bytes()
}

// String returns a decimal representation of the element suitable for
// logs and error messages. Not constant-time; do not use on paths that
// handle secrets in production.
func (u *UnitTrait[A, W, WT]) String() string {
	return u.v.String()
}
