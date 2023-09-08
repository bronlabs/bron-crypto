package lindell17

import (
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/signing"
)

func (p *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell17.PartialSignature, err error) {
	bigR := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].BigR[p.theirIdentityKey.Hash()]
	bigRx := bigR.X().Nat()
	r, err := p.cohortConfig.CipherSuite.Curve.Scalar().SetNat(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	paillierPublicKey := p.myShard.PaillierPublicKeys[p.theirIdentityKey.Hash()]
	cKey := p.myShard.PaillierEncryptedShares[p.theirIdentityKey.Hash()]
	k2 := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].K
	shamirShare := &shamir.Share{
		Id:    p.mySharingId,
		Value: p.myShard.SigningKeyShare.Share,
	}
	additiveShare, err := shamirShare.ToAdditive([]int{p.mySharingId, p.theirSharingId})
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my additive share")
	}

	theirLambda, err := signing.CalcOtherPartyLagrangeCoefficient(p.theirSharingId, p.mySharingId, p.cohortConfig.Protocol.TotalParties, p.cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate Lagrange coefficients")
	}
	q := p.cohortConfig.CipherSuite.Curve.Profile().SubGroupOrder()
	mPrime, err := signing.MessageToScalar(p.cohortConfig.CipherSuite.Hash, p.cohortConfig.CipherSuite.Curve, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get scalar from message")
	}

	// c3 = Enc_pk(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
	c3, err := signing.CalcC3(theirLambda, k2, mPrime, r, additiveShare, q.Nat(), paillierPublicKey, cKey, p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate c3")
	}

	return &lindell17.PartialSignature{
		C3: c3,
	}, nil
}

func (p *Cosigner) ProduceSignature(theirPartialSignature *lindell17.PartialSignature, message []byte) (sigma *ecdsa.Signature, err error) {
	bigR := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].BigR[p.theirIdentityKey.Hash()]
	bigRx := bigR.X().Nat()
	r, err := p.cohortConfig.CipherSuite.Curve.Scalar().SetNat(bigRx)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get R.x")
	}

	paillierSecretKey := p.myShard.PaillierSecretKey
	decryptor, err := paillier.NewDecryptor(paillierSecretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create paillier decryptor")
	}
	sPrimeInt, err := decryptor.Decrypt(theirPartialSignature.C3)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt c3")
	}
	sPrime, err := p.cohortConfig.CipherSuite.Curve.Scalar().SetNat(sPrimeInt)
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
	//if err := ecdsa.Verify(sigma, p.cohortConfig.CipherSuite.Hash, p.myShard.SigningKeyShare.PublicKey, message); err != nil {
	//	return nil, errs.WrapVerificationFailed(err, "could not verify produced signature")
	//}
	return sigma, nil
}
