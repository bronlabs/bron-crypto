package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/signing"
)

func (p *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell17.PartialSignature, err error) {
	bigR := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].BigR[p.theirIdentityKey]
	bigRx, _ := lindell17.GetPointCoordinates(bigR)
	r, err := p.cohortConfig.CipherSuite.Curve.Scalar.SetBigInt(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	paillierPublicKey := p.myShard.PaillierPublicKeys[p.theirIdentityKey]
	cKey := p.myShard.PaillierEncryptedShares[p.theirIdentityKey]
	k2 := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].K
	share := p.myShard.SigningKeyShare.Share
	lambda1, lambda2, err := signing.CalcLagrangeCoefficients(p.theirShamirId, p.myShamirId, p.cohortConfig.TotalParties, p.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate Lagrange coefficients")
	}
	q, err := lindell17.GetCurveOrder(p.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate subgroup order")
	}
	mPrime, err := signing.MessageToScalar(p.cohortConfig.CipherSuite.Hash, p.cohortConfig.CipherSuite.Curve, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get scalar from message")
	}

	// c3 = Enc_pk(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := signing.CalcC3(lambda1, lambda2, k2, mPrime, r, share, q, paillierPublicKey, cKey, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate c3")
	}

	return &lindell17.PartialSignature{
		C3: c3,
	}, nil
}

func (p *Cosigner) ProduceSignature(theirPartialSignature *lindell17.PartialSignature, message []byte) (sigma *ecdsa.Signature, err error) {
	bigR := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].BigR[p.theirIdentityKey]
	bigRx, _ := lindell17.GetPointCoordinates(bigR)
	r, err := p.cohortConfig.CipherSuite.Curve.Scalar.SetBigInt(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	paillierSecretKey := p.myShard.PaillierSecretKey
	sPrimeInt, err := paillierSecretKey.Decrypt(theirPartialSignature.C3)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt c3")
	}
	sPrime, err := p.cohortConfig.CipherSuite.Curve.NewScalar().SetBigInt(sPrimeInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar value")
	}

	k1Inv, err := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].K.Invert()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot invert k1")
	}
	sDoublePrime := k1Inv.Mul(sPrime)

	sigma = &ecdsa.Signature{
		R: r,
		S: sDoublePrime,
	}
	v, err := ecdsa.CalculateRecoveryId(bigR)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute recovery id")
	}
	sigma.V = &v
	if err := ecdsa.Verify(sigma, p.cohortConfig.CipherSuite.Hash, p.myShard.SigningKeyShare.PublicKey, message); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not verify produced signature")
	}
	return sigma, nil
}
