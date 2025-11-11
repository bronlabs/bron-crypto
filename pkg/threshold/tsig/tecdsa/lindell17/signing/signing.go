package signing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/cronokirby/saferith"
)

// CalcC3 calculates Enc_pk(ρq + k2^(-1)(m' + r * (cKey * λ1 + share * λ2))), ρ is chosen randomly: 0 < ρ < pk^2.
func CalcC3(lambda1, k2, mPrime, r, additiveShare curves.Scalar, q *saferith.Nat, pk *paillier.PublicKey, cKey *paillier.CipherText, prng io.Reader) (c3 *paillier.CipherText, err error) {
	k2Inv, err := k2.MultiplicativeInverse()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get k2 inverse")
	}

	// c1 = Enc(ρq + k2^(-1) * m')
	c1Plain := k2Inv.Mul(mPrime).Nat()
	qSquared := new(saferith.Nat).Mul(q, q, -1)
	rho, err := saferithUtils.NatRandomRangeH(prng, qSquared)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random int")
	}
	rhoMulQ := new(saferith.Nat).ModMul(rho, q, saferith.ModulusFromNat(qSquared))
	c1, _, err := pk.Encrypt(new(saferith.Int).SetNat(new(saferith.Nat).ModAdd(rhoMulQ, c1Plain, saferith.ModulusFromNat(qSquared))), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c1")
	}

	// c2 = Enc(k2^(-1) * r * (cKey * λ1 + share * λ2))
	c2Left, err := pk.CipherTextMul(cKey, new(saferith.Int).SetNat(k2Inv.Mul(r).Mul(lambda1).Nat()))
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic multiplication failed")
	}
	c2Right, _, err := pk.Encrypt(new(saferith.Int).SetNat(k2Inv.Mul(r).Mul(additiveShare).Nat()), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c2")
	}
	c2, err := pk.CipherTextAdd(c2Left, c2Right)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic addition failed")
	}

	// c3 = c1 + c2 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err = pk.CipherTextAdd(c1, c2)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic addition failed")
	}

	return c3, nil
}

func MessageToScalar[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](cipherSuite *ecdsa.Suite[P, B, S], message []byte) (S, error) {
	messageHash, err := hashing.Hash(cipherSuite.HashFunc(), message)
	if err != nil {
		return *new(S), errs.WrapHashing(err, "cannot hash message")
	}
	sc, err := ecdsa.DigestToScalar(cipherSuite.ScalarField(), messageHash)
	if err != nil {
		return *new(S), errs.WrapFailed(err, "cannot convert digest to scalar")
	}
	return sc, nil
}
