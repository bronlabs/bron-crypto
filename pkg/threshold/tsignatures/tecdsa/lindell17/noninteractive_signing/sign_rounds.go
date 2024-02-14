package noninteractive_signing

// import (
// 	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
// 	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
// 	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
// 	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
// ).

// func (p *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell17.PartialSignature, err error) {
// 	bigR, exists := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].BigR.Get(p.theirIdentityKey)
// 	if !exists {
// 		return nil, errs.NewMissing("corresponding bigR does not exist")
// 	}
// 	bigRx := bigR.AffineX().Nat()
// 	r := p.protocol.Curve().Scalar().SetNat(bigRx)

// 	paillierPublicKey, exists := p.myShard.PaillierPublicKeys.Get(p.theirIdentityKey)
// 	if !exists {
// 		return nil, errs.NewMissing("their public key is missing")
// 	}
// 	cKey, exists := p.myShard.PaillierEncryptedShares.Get(p.theirIdentityKey)
// 	if !exists {
// 		return nil, errs.NewMissing("their paillier encrypted share is missing")
// 	}
// 	k2 := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].K
// 	shamirShare := &shamir.Share{
// 		Id:    p.mySharingId,
// 		Value: p.myShard.SigningKeyShare.Share,
// 	}
// 	additiveShare, err := shamirShare.ToAdditive([]int{p.mySharingId, p.theirSharingId})
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not derive my additive share")
// 	}

// 	theirLambda, err := interactive_signing.CalcOtherPartyLagrangeCoefficient(p.theirSharingId, p.mySharingId, p.protocol.TotalParties(), p.protocol.Curve())
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "cannot calculate Lagrange coefficients")
// 	}
// 	q := p.protocol.Curve().SubGroupOrder()
// 	mPrime, err := interactive_signing.MessageToScalar(p.protocol.Hash(), p.protocol.Curve(), message)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "cannot get scalar from message")
// 	}

// 	// c3 = Enc_pk(ρq + k2^(-1)(m' + r * (y1 * λ1 + y2 * λ2)))
// 	c3, err := interactive_signing.CalcC3(theirLambda, k2, mPrime, r, additiveShare, q.Nat(), paillierPublicKey, cKey, p.prng)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "cannot calculate c3")
// 	}

// 	return &lindell17.PartialSignature{
// 		C3: c3,
// 	}, nil
// }.

// func (p *Cosigner) ProduceSignature(theirPartialSignature *lindell17.PartialSignature, message []byte) (sigma *ecdsa.Signature, err error) {
// 	bigR, exists := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].BigR.Get(p.theirIdentityKey)
// 	if !exists {
// 		return nil, errs.NewMissing("corresponding bigR does not exist")
// 	}
// 	bigRx := bigR.AffineX().Nat()
// 	r := p.protocol.Curve().Scalar().SetNat(bigRx)

// 	paillierSecretKey := p.myShard.PaillierSecretKey
// 	decryptor, err := paillier.NewDecryptor(paillierSecretKey)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "cannot create paillier decryptor")
// 	}
// 	sPrimeInt, err := decryptor.Decrypt(theirPartialSignature.C3)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "cannot decrypt c3")
// 	}
// 	sPrime := p.protocol.Curve().Scalar().SetNat(sPrimeInt)

// 	k1Inv := p.myPreSignatureBatch.PreSignatures[p.preSignatureIndex].K.MultiplicativeInverse()
// 	sDoublePrime := k1Inv.Mul(sPrime)

// 	sigma = &ecdsa.Signature{
// 		R: r,
// 		S: sDoublePrime,
// 	}
// 	v, err := ecdsa.CalculateRecoveryId(bigR)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not compute recovery id")
// 	}
// 	sigma.V = &v
// 	if err := ecdsa.Verify(sigma, p.protocol.Hash(), p.myShard.SigningKeyShare.PublicKey, message); err != nil {
// 		return nil, errs.WrapVerificationFailed(err, "could not verify produced signature")
// 	}
// 	return sigma, nil
// }.
