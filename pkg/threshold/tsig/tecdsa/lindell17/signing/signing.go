package signing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/errs-go/errs"
)

// CalcC3 calculates Enc_pk(ρq + k2^(-1)(m' + r * (cKey * λ + share * λ))).
func CalcC3[S algebra.PrimeFieldElement[S]](lambda, k2, mPrime, r, additiveShare S, curveOrder algebra.Cardinal, pk *paillier.PublicKey, cKey *paillier.Ciphertext, prng io.Reader) (c3 *paillier.Ciphertext, err error) {
	k2Inv, err := k2.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get k2 inverse")
	}

	qNat, err := num.NPlus().FromCardinal(curveOrder)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert q to Nat")
	}
	zModQ2, err := num.NewZMod(qNat.Square())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ZMod q^2")
	}
	q, err := zModQ2.FromNatPlus(qNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert qNat to ZMod q^2")
	}

	// c1 = Enc(ρq + k2^(-1) * m')
	c1Plain := k2Inv.Mul(mPrime)
	rho, err := zModQ2.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate random int")
	}
	rhoMulQ := rho.Mul(q)

	c1PlainUint, err := zModQ2.FromNatCTReduced(numct.NewNatFromBytes(c1Plain.Bytes()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert c1Plain to ZMod q^2")
	}
	c1Message, err := pk.PlaintextSpace().FromNat(rhoMulQ.Add(c1PlainUint).Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert c1PlainUint to plaintext")
	}

	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create paillier encrypter")
	}
	c1, _, err := enc.Encrypt(c1Message, pk, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt c1")
	}

	// c2 = Enc(k2^(-1) * r * (cKey * λ + share * λ))
	c2LeftExponent, err := num.N().FromBytes(k2Inv.Mul(r).Mul(lambda).Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert c2 left exponent to Nat")
	}
	c2Left := cKey.ScalarMul(c2LeftExponent)

	c2RightMessage, err := pk.PlaintextSpace().FromBytes(k2Inv.Mul(r).Mul(additiveShare).Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert c2 right message to plaintext")
	}
	c2Right, _, err := enc.Encrypt(c2RightMessage, pk, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt c2")
	}
	c2 := c2Left.HomAdd(c2Right)

	// c3 = c1 + c2 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ + y2 * λ)))
	c3 = c1.HomAdd(c2)

	return c3, nil
}

// MessageToScalar hashes a message into a curve scalar.
func MessageToScalar[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](cipherSuite *ecdsa.Suite[P, B, S], message []byte) (S, error) {
	messageHash, err := hashing.Hash(cipherSuite.HashFunc(), message)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot hash message")
	}
	sc, err := ecdsa.DigestToScalar(cipherSuite.ScalarField(), messageHash)
	if err != nil {
		return *new(S), errs.Wrap(err).WithMessage("cannot convert digest to scalar")
	}
	return sc, nil
}
