//go:build !purego && !nobignum

package nt

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// Jacobi returns the Jacobi symbol (a/n) for a positive odd n, delegating to
// BoringSSL's BN_jacobi. Negative a is reduced mod n before the call because
// BoringSSL rejects negative inputs; the result is unaffected since the Jacobi
// symbol depends only on a mod n.
//
// NOT constant time: BN_jacobi uses a variable-time binary GCD-style reduction
// whose control flow depends on the magnitudes and bit patterns of a and n.
// Do not use on secret inputs.
func Jacobi(a *num.Int, n *num.NatPlus) (int, error) {
	if n.IsEven() {
		return -2, ErrInvalidArgument.WithMessage("Jacobi symbol is only defined for odd positive n")
	}
	effectiveA := a.Clone()
	if a.IsNegative() { // BoringSSL does not support negative inputs for Jacobi, so we take the absolute value and adjust the result accordingly
		effectiveA = effectiveA.Mod(n).Lift()
	}
	// effectiveA.Bytes() is sign encoded
	aBytes, nBytes := effectiveA.Bytes()[1:], n.Bytes()
	aNum, err := boring.NewBigNum().SetBytes(aBytes)
	if err != nil {
		return -2, errs.Wrap(err).WithMessage("failed to create BigNum for a")
	}
	bNum, err := boring.NewBigNum().SetBytes(nBytes)
	if err != nil {
		return -2, errs.Wrap(err).WithMessage("failed to create BigNum for n")
	}
	bnCtx := boring.NewBigNumCtx()
	jacobi, err := aNum.Jacobi(bNum, bnCtx)
	if err != nil {
		return -2, errs.Wrap(err).WithMessage("failed to compute Jacobi symbol")
	}
	return jacobi, nil
}
