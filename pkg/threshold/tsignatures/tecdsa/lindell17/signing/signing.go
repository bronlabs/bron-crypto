package signing

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
)

// CalcOtherPartyLagrangeCoefficient computes Lagrange coefficient of there other party.
func CalcOtherPartyLagrangeCoefficient(otherPartySharingId, mySharingId types.SharingID, n uint, curve curves.Curve) (curves.Scalar, error) {
	dealer, err := shamir.NewDealer(lindell17.Threshold, n, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create shamir dealer")
	}
	coefficients, err := dealer.LagrangeCoefficients([]uint{uint(otherPartySharingId), uint(mySharingId)})
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get Lagrange coefficients")
	}
	return coefficients[uint(otherPartySharingId)], nil
}

// CalcC3 calculates Enc_pk(ρq + k2^(-1)(m' + r * (cKey * λ1 + share * λ2))), ρ is chosen randomly: 0 < ρ < pk^2.
func CalcC3(lambda1, k2, mPrime, r, additiveShare curves.Scalar, q *saferith.Nat, pk *paillier.PublicKey, cKey *paillier.CipherText, prng io.Reader) (c3 *paillier.CipherText, err error) {
	k2Inv := k2.MultiplicativeInverse()

	// c1 = Enc(ρq + k2^(-1) * m')
	c1Plain := k2Inv.Mul(mPrime).Nat()
	qSquared := new(saferith.Nat).Mul(q, q, -1)
	rho, err := utils.RandomNatRange(prng, new(saferith.Nat).SetUint64(0), qSquared)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random int")
	}
	rhoMulQ := new(saferith.Nat).ModMul(rho, q, saferith.ModulusFromNat(qSquared))
	c1, _, err := pk.Encrypt(new(saferith.Nat).ModAdd(rhoMulQ, c1Plain, saferith.ModulusFromNat(qSquared)), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt c1")
	}

	// c2 = Enc(k2^(-1) * r * (cKey * λ1 + share * λ2))
	c2Left, err := pk.MulPlaintext(cKey, k2Inv.Mul(r).Mul(lambda1).Nat())
	if err != nil {
		return nil, errs.WrapFailed(err, "homomorphic multiplication failed")
	}
	c2Right, _, err := pk.Encrypt(k2Inv.Mul(r).Mul(additiveShare).Nat(), prng)
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

func MessageToScalar(cipherSuite types.SigningSuite, message []byte) (curves.Scalar, error) {
	messageHash, err := hashing.Hash(cipherSuite.Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	mPrimeUint := ecdsa.BitsToInt(messageHash, cipherSuite.Curve())
	mPrime, err := cipherSuite.Curve().Scalar().SetBytes(mPrimeUint.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot convert message to scalar")
	}
	return mPrime, nil
}
