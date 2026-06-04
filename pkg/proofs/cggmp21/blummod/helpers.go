package blummod

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func validateWitness(statement *Statement, witness *Witness) error {
	if statement == nil {
		return ErrInvalidArgument.WithMessage("statement must not be nil")
	}
	if witness == nil {
		return ErrInvalidArgument.WithMessage("witness must not be nil")
	}
	if !witness.secretKey.Group().N().Equal(statement.publicKey.Group().N()) {
		return ErrValidationFailed.WithMessage("witness secret key does not match protocol Paillier modulus")
	}
	return nil
}

func minusOne(publicKey *paillier.PublicKey) (*paillier.Nonce, error) {
	if publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("publicKey must not be nil")
	}
	value, err := minusOneUnknown(publicKey.NonceGroup())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create -1")
	}
	nonce, err := paillier.NewNonceFromGroupElement(value)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create -1 nonce")
	}
	return nonce, nil
}

func validatePublicModulus(n *num.NatPlus) error {
	if n == nil {
		return ErrInvalidArgument.WithMessage("N must not be nil")
	}
	minModulus, err := num.NPlus().FromUint64(9)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create minimum modulus")
	}
	if n.Compare(minModulus).IsLessThan() {
		return ErrValidationFailed.WithMessage("N must be an odd composite greater than 1")
	}
	if !n.IsOdd() {
		return ErrValidationFailed.WithMessage("N must be odd")
	}
	if n.IsProbablyPrime() {
		return ErrValidationFailed.WithMessage("N must be composite")
	}
	return nil
}

func rsaGroupFromWitness(witness *Witness) (*znstar.RSAGroupKnownOrder, error) {
	arithmetic := witness.secretKey.Group().Arithmetic().CrtModN
	p, err := num.NPlus().FromNatCT(arithmetic.Params.PNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert p")
	}
	q, err := num.NPlus().FromNatCT(arithmetic.Params.QNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert q")
	}
	out, err := znstar.NewRSAGroup(p, q)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create RSA group")
	}
	return out, nil
}

func minusOneKnown(group *znstar.RSAGroupKnownOrder) (*znstar.RSAGroupElementKnownOrder, error) {
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group must not be nil")
	}
	elem, err := group.FromNatCT(minusOneNat(group.Modulus()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create known-order -1")
	}
	return elem, nil
}

func minusOneUnknown(group *znstar.RSAGroupUnknownOrder) (*znstar.RSAGroupElementUnknownOrder, error) {
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group must not be nil")
	}
	elem, err := group.FromNatCT(minusOneNat(group.Modulus()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create unknown-order -1")
	}
	return elem, nil
}

func minusOneNat(modulus *num.NatPlus) *numct.Nat {
	out := modulus.Value().Clone()
	out.Decrement()
	return out
}

func nInverseModPhi(secretKey *paillier.SecretKey) (*num.Nat, error) {
	if secretKey == nil {
		return nil, ErrInvalidArgument.WithMessage("secretKey must not be nil")
	}
	arithmetic := secretKey.Group().Arithmetic().CrtModN
	var inv numct.Nat
	if arithmetic.Phi.ModInv(&inv, arithmetic.N.Nat()) == ct.False {
		return nil, ErrValidationFailed.WithMessage("N is not invertible modulo phi(N)")
	}
	out, err := num.N().FromNatCT(&inv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert N inverse mod phi(N)")
	}
	return out, nil
}

func fourthRootExponent(secretKey *paillier.SecretKey) (*num.Nat, error) {
	if secretKey == nil {
		return nil, ErrInvalidArgument.WithMessage("secretKey must not be nil")
	}
	arithmetic := secretKey.Group().Arithmetic().CrtModN
	if !isThreeModFour(arithmetic.Params.PNat) || !isThreeModFour(arithmetic.Params.QNat) {
		return nil, ErrValidationFailed.WithMessage("p and q must be 3 mod 4")
	}
	phi := arithmetic.Phi.Nat()
	var phiPlusFour numct.Nat
	phiPlusFour.Add(phi, numct.NewNat(4))

	var sqrtExp numct.Nat
	sqrtExp.Rsh(&phiPlusFour, 3)

	var fourthRootExp numct.Nat
	fourthRootExp.Mul(&sqrtExp, &sqrtExp)

	out, err := num.N().FromNatCT(&fourthRootExp)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert fourth-root exponent")
	}
	return out, nil
}

func isThreeModFour(n *numct.Nat) bool {
	if n == nil {
		return false
	}
	return n.Bit(0) == 1 && n.Bit(1) == 1
}
