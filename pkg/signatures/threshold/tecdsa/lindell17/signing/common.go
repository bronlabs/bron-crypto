package signing

import (
	crand "crypto/rand"
	"hash"
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
)

// CalcOtherPartyLagrangeCoefficient computes Lagrange coefficient of there other party.
func CalcOtherPartyLagrangeCoefficient(otherPartySharingId, mySharingId, n int, curve *curves.Curve) (curves.Scalar, error) {
	dealer, err := shamir.NewDealer(lindell17.Threshold, n, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create shamir dealer")
	}
	coefficients, err := dealer.LagrangeCoefficients([]int{otherPartySharingId, mySharingId})
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get Lagrange coefficients")
	}
	return coefficients[otherPartySharingId], nil
}

// CalcC3 calculates Enc_pk(ρq + k2^(-1)(m' + r * (cKey * λ1 + share * λ2))), ρ is chosen randomly: 0 < ρ < pk^2.
func CalcC3(lambda1, k2, mPrime, r, additiveShare curves.Scalar, q *big.Int, pk *paillier.PublicKey, cKey paillier.CipherText, prng io.Reader) (c3 paillier.CipherText, err error) {
	k2Inv, err := k2.Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot invert k2")
	}

	// c1 = Enc(ρq + k2^(-1) * m')
	c1Plain := k2Inv.Mul(mPrime).BigInt()
	qSquared := new(big.Int).Mul(q, q)
	rho, err := crand.Int(prng, qSquared)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random int")
	}
	rhoMulQ := new(big.Int).Mul(rho, q)
	c1, _, err := pk.Encrypt(new(big.Int).Add(rhoMulQ, c1Plain))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c1")
	}

	// c2 = Enc(k2^(-1) * r * (cKey * λ1 + share * λ2))
	c2Left, err := pk.Mul(k2Inv.Mul(r).Mul(lambda1).BigInt(), cKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic multiplication failed")
	}
	c2Right, _, err := pk.Encrypt(k2Inv.Mul(r).Mul(additiveShare).BigInt())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c2")
	}
	c2, err := pk.Add(c2Left, c2Right)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic addition failed")
	}

	// c3 = c1 + c2 = Enc(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err = pk.Add(c1, c2)
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic addition failed")
	}

	return c3, nil
}

func MessageToScalar(hashFunc func() hash.Hash, curve *curves.Curve, message []byte) (curves.Scalar, error) {
	messageHash, err := hashing.Hash(hashFunc, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash message")
	}
	mPrimeInt, err := lindell17.DigestToInt(messageHash, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create int from hash")
	}
	mPrime, err := curve.NewScalar().SetBigInt(mPrimeInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash to scalar")
	}

	return mPrime, nil
}
