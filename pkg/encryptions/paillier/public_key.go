package paillier

import (
	crand "crypto/rand"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type PublicKeyPrecomputed struct {
	G         *saferith.Nat
	NModulus  *saferith.Modulus
	N2Modulus *saferith.Modulus
}

type PublicKey struct {
	N           *saferith.Nat
	precomputed *PublicKeyPrecomputed
}

func NewPublicKey(n *saferith.Nat) (*PublicKey, error) {
	if n == nil {
		return nil, errs.NewIsNil("n")
	}

	pk := &PublicKey{N: n}
	pk.precompute()
	return pk, nil
}

func (pk *PublicKey) GetPrecomputed() *PublicKeyPrecomputed {
	if pk.precomputed == nil {
		pk.precompute()
	}

	return pk.precomputed
}

func (pk *PublicKey) Add(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid rhs")
	}

	n2 := pk.GetPrecomputed().N2Modulus

	return &CipherText{
		C: new(saferith.Nat).ModMul(lhs.C, rhs.C, n2),
	}, nil
}

func (pk *PublicKey) AddPlaintext(lhs *CipherText, rhs *saferith.Nat) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !isLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	n2 := pk.GetPrecomputed().N2Modulus
	g := pk.GetPrecomputed().G
	rhsC := new(saferith.Nat).Exp(g, rhs, n2)
	result := new(saferith.Nat).ModMul(lhs.C, rhsC, n2)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) Sub(lhs, rhs *CipherText) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if err := rhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid rhs")
	}

	n2 := pk.GetPrecomputed().N2Modulus
	rhsInv := new(saferith.Nat).ModInverse(rhs.C, n2)
	result := new(saferith.Nat).ModMul(lhs.C, rhsInv, n2)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) SubPlaintext(lhs *CipherText, rhs *saferith.Nat) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !isLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	n2 := pk.GetPrecomputed().N2Modulus
	n := pk.GetPrecomputed().NModulus
	g := pk.GetPrecomputed().G
	rhsNeg := new(saferith.Nat).ModNeg(rhs, n)
	rhsCInv := new(saferith.Nat).Exp(g, rhsNeg, n2)
	result := new(saferith.Nat).ModMul(lhs.C, rhsCInv, n2)

	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) MulPlaintext(lhs *CipherText, rhs *saferith.Nat) (*CipherText, error) {
	if err := lhs.Validate(pk); err != nil {
		return nil, errs.WrapFailed(err, "invalid lhs")
	}
	if rhs == nil || !isLess(rhs, pk.N) {
		return nil, errs.NewFailed("invalid rhs")
	}

	n2 := pk.GetPrecomputed().N2Modulus
	result := new(saferith.Nat).Exp(lhs.C, rhs, n2)
	return &CipherText{
		C: result,
	}, nil
}

func (pk *PublicKey) EncryptWithNonce(plainText, nonce *saferith.Nat) (*CipherText, error) {
	if plainText == nil || !isLess(plainText, pk.N) {
		return nil, errs.NewFailed("invalid plainText")
	}
	n := pk.GetPrecomputed().NModulus
	if nonce == nil || nonce.EqZero() == 1 || !isLess(nonce, pk.N) || nonce.IsUnit(n) != 1 {
		return nil, errs.NewFailed("invalid nonce")
	}

	g := pk.GetPrecomputed().G
	n2 := pk.GetPrecomputed().N2Modulus
	gToM := new(saferith.Nat).Exp(g, plainText, n2)
	rToN := new(saferith.Nat).Exp(nonce, pk.N, n2)
	cipherText := new(saferith.Nat).ModMul(gToM, rToN, n2)

	return &CipherText{
		C: cipherText,
	}, nil
}

func (pk *PublicKey) Encrypt(plainText *saferith.Nat, prng io.Reader) (*CipherText, *saferith.Nat, error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	if plainText == nil || !isLess(plainText, pk.N) {
		return nil, nil, errs.NewFailed("invalid plainText")
	}

	n := pk.GetPrecomputed().NModulus
	var nonce *saferith.Nat
	for {
		nonceBig, err := crand.Int(prng, pk.N.Big())
		if err != nil {
			return nil, nil, errs.NewRandomSample("cannot sample nonce")
		}
		nonce = new(saferith.Nat).SetBig(nonceBig, pk.N.AnnouncedLen())
		if nonce.EqZero() != 1 && nonce.IsUnit(n) == 1 {
			break
		}
	}

	cipherText, err := pk.EncryptWithNonce(plainText, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot encrypt")
	}

	return cipherText, nonce, nil
}

func (pk *PublicKey) Validate() error {
	if pk == nil {
		return errs.NewIsNil("sk")
	}
	if pk.N == nil {
		return errs.NewIsNil("n")
	}

	return nil
}

func (pk *PublicKey) precompute() {
	nMod := saferith.ModulusFromNat(pk.N)
	n2 := new(saferith.Nat).Mul(pk.N, pk.N, -1)
	n2Mod := saferith.ModulusFromNat(n2)
	g := new(saferith.Nat).Add(pk.N, new(saferith.Nat).SetUint64(1), pk.N.AnnouncedLen())
	pk.precomputed = &PublicKeyPrecomputed{
		G:         g,
		NModulus:  nMod,
		N2Modulus: n2Mod,
	}
}

func isLess(l, r *saferith.Nat) bool {
	_, _, less := l.Cmp(r)
	return less == 1
}
