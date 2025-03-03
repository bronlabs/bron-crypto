package interactive_signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21"
	"github.com/cronokirby/saferith"
	"io"
	"maps"
	"slices"
)

func (c *Cosigner) Round1() (r1bOut *Round1Broadcast, err error) {
	c.state.k, err = c.Protocol.Curve().ScalarField().Random(c.Prng)
	if err != nil {
		return nil, err
	}
	c.state.gamma, err = c.Protocol.Curve().ScalarField().Random(c.Prng)
	if err != nil {
		return nil, err
	}

	c.state.bigK = make(map[types.SharingID]*paillier.CipherText)
	c.state.bigK[c.MySharingId], _, err = c.MyShard.PaillierSecretKey.Encrypt(mapScalarToPaillierPlaintext(c.state.k), c.Prng)
	c.state.bigG = make(map[types.SharingID]*paillier.CipherText)
	c.state.bigG[c.MySharingId], _, err = c.MyShard.PaillierSecretKey.Encrypt(mapScalarToPaillierPlaintext(c.state.gamma), c.Prng)

	r1bOut = &Round1Broadcast{
		BigK: c.state.bigK[c.MySharingId],
		BigG: c.state.bigG[c.MySharingId],
	}

	return r1bOut, nil
}

func (c *Cosigner) Round2(r2bIn network.RoundMessages[types.ThresholdSignatureProtocol, *Round1Broadcast]) (r2bOut *Round2Broadcast, r2uOut network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P], err error) {
	for sharingId, identityKey := range c.QuorumIdentities {
		if sharingId == c.MySharingId {
			continue
		}

		in, _ := r2bIn.Get(identityKey)
		c.state.bigK[sharingId] = in.BigK
		c.state.bigG[sharingId] = in.BigG
	}

	beta := make(map[types.SharingID]*paillier.PlainText)
	betaDash := make(map[types.SharingID]*paillier.PlainText)
	bigD := make(map[types.SharingID]*paillier.CipherText)
	bigDDash := make(map[types.SharingID]*paillier.CipherText)
	bigF := make(map[types.SharingID]*paillier.CipherText)
	bigFDash := make(map[types.SharingID]*paillier.CipherText)
	c.state.betaSum = new(saferith.Int)
	c.state.betaDashSum = new(saferith.Int)
	for sharingId := range c.QuorumIdentities {
		if sharingId == c.MySharingId {
			continue
		}

		beta[sharingId], err = sampleJRange(c.Prng)
		if err != nil {
			return nil, nil, err
		}
		c.state.betaSum.Add(c.state.betaSum, beta[sharingId], -1)
		betaDash[sharingId], err = sampleJRange(c.Prng)
		if err != nil {
			return nil, nil, err
		}
		c.state.betaDashSum.Add(c.state.betaDashSum, betaDash[sharingId], -1)

		paillierPk, _ := c.MyShard.PaillierPublicKeys.Get(sharingId)
		encBeta, _, err := paillierPk.Encrypt(beta[sharingId], c.Prng)
		if err != nil {
			return nil, nil, err
		}
		encBetaDash, _, err := paillierPk.Encrypt(betaDash[sharingId], c.Prng)
		if err != nil {
			return nil, nil, err
		}

		gk, err := paillierPk.CipherTextMul(c.state.bigK[sharingId], mapScalarToPaillierPlaintext(c.state.gamma))
		if err != nil {
			return nil, nil, err
		}
		bigD[sharingId], err = paillierPk.CipherTextSub(gk, encBeta)
		if err != nil {
			return nil, nil, err
		}

		x, err := (&shamir.Share{
			Id:    c.MySharingId,
			Value: c.MyShard.Share.Share,
		}).ToAdditive(slices.Collect(maps.Keys(c.QuorumIdentities)))
		if err != nil {
			return nil, nil, err
		}
		xk, err := paillierPk.CipherTextMul(c.state.bigK[sharingId], mapScalarToPaillierPlaintext(x))
		if err != nil {
			return nil, nil, err
		}
		bigDDash[sharingId], err = paillierPk.CipherTextSub(xk, encBetaDash)
		if err != nil {
			return nil, nil, err
		}

		bigF[sharingId], _, err = c.MyShard.PaillierSecretKey.Encrypt(beta[sharingId], c.Prng)
		if err != nil {
			return nil, nil, err
		}

		bigFDash[sharingId], _, err = c.MyShard.PaillierSecretKey.Encrypt(betaDash[sharingId], c.Prng)
		if err != nil {
			return nil, nil, err
		}
	}
	c.state.bigGamma = c.Protocol.Curve().ScalarBaseMult(c.state.gamma)

	r2bOut = &Round2Broadcast{
		BigGamma: c.state.bigGamma,
	}

	r2uOut = network.NewRoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]()
	for sharingId, identityKey := range c.QuorumIdentities {
		if sharingId == c.MySharingId {
			continue
		}

		r2uOut.Put(identityKey, &Round2P2P{
			BigD:     bigD[sharingId],
			BigDDash: bigDDash[sharingId],
			BigF:     bigF[sharingId],
			BigFDash: bigFDash[sharingId],
		})
	}

	return r2bOut, r2uOut, nil
}

func (c *Cosigner) Round3(r3bIn network.RoundMessages[types.ThresholdSignatureProtocol, *Round2Broadcast], r3uIn network.RoundMessages[types.ThresholdSignatureProtocol, *Round2P2P]) (r3bOut *Round3Broadcast, err error) {
	//alpha := make(map[types.SharingID]curves.Scalar)
	//alphaDash := make(map[types.SharingID]curves.Scalar)
	alphaSum := c.Protocol.Curve().ScalarField().AdditiveIdentity()
	alphaDashSum := c.Protocol.Curve().ScalarField().AdditiveIdentity()
	for sharingId, identityKey := range c.QuorumIdentities {
		if sharingId == c.MySharingId {
			continue
		}
		bIn, _ := r3bIn.Get(identityKey)
		uIn, _ := r3uIn.Get(identityKey)

		c.state.bigGamma = c.state.bigGamma.Add(bIn.BigGamma)

		alphaPlaintext, err := c.MyShard.PaillierSecretKey.Decrypt(uIn.BigD)
		if err != nil {
			return nil, err
		}
		alpha := mapPaillierPlaintextToScalar(c.Protocol.Curve().ScalarField(), alphaPlaintext)
		alphaSum = alphaSum.Add(alpha)

		alphaDashPlaintext, err := c.MyShard.PaillierSecretKey.Decrypt(uIn.BigDDash)
		if err != nil {
			return nil, err
		}
		alphaDash := mapPaillierPlaintextToScalar(c.Protocol.Curve().ScalarField(), alphaDashPlaintext)
		alphaDashSum = alphaDashSum.Add(alphaDash)
	}

	x, err := (&shamir.Share{
		Id:    c.MySharingId,
		Value: c.MyShard.Share.Share,
	}).ToAdditive(slices.Collect(maps.Keys(c.QuorumIdentities)))
	if err != nil {
		return nil, err
	}

	c.state.delta = c.state.gamma.Mul(c.state.k).Add(alphaSum).Add(mapPaillierPlaintextToScalar(c.Protocol.Curve().ScalarField(), c.state.betaSum))
	c.state.chi = x.Mul(c.state.k).Add(alphaDashSum).Add(mapPaillierPlaintextToScalar(c.Protocol.Curve().ScalarField(), c.state.betaDashSum))
	c.state.bigDelta = c.state.bigGamma.ScalarMul(c.state.k)
	c.state.bigS = c.state.bigGamma.ScalarMul(c.state.chi)

	r3bOut = &Round3Broadcast{
		Delta:    c.state.delta,
		BigDelta: c.state.bigDelta,
		BigS:     c.state.bigS,
	}
	return r3bOut, nil
}

func (c *Cosigner) Round4(r4bIn network.RoundMessages[types.ThresholdSignatureProtocol, *Round3Broadcast], message []byte) (partialSignature *cggmp21.PartialSignature, err error) {
	for sharingId, identityKey := range c.QuorumIdentities {
		if sharingId == c.MySharingId {
			continue
		}
		bIn, _ := r4bIn.Get(identityKey)

		c.state.delta = c.state.delta.Add(bIn.Delta)
		c.state.bigDelta = c.state.bigDelta.Add(bIn.BigDelta)
		c.state.bigS = c.state.bigS.Add(bIn.BigS)
	}

	kTilde, err := c.state.k.Div(c.state.delta)
	if err != nil {
		return nil, err
	}
	chiTilde, err := c.state.chi.Div(c.state.delta)
	if err != nil {
		return nil, err
	}
	// TODO: add verification

	m, err := messageToScalar(c.Protocol.SigningSuite(), message)
	if err != nil {
		return nil, err
	}
	r, err := c.Protocol.SigningSuite().Curve().ScalarField().Element().SetBytesWide(c.state.bigGamma.AffineX().Bytes())
	if err != nil {
		return nil, err
	}
	sigma := kTilde.Mul(m).Add(r.Mul(chiTilde))
	partialSignature = &cggmp21.PartialSignature{
		R: r,
		S: sigma,
	}

	return partialSignature, nil
}

func mapScalarToPaillierPlaintext(s curves.Scalar) *paillier.PlainText {
	return new(saferith.Int).SetModSymmetric(s.Nat(), s.ScalarField().Order())
}

func mapPaillierPlaintextToScalar(field curves.ScalarField, p *paillier.PlainText) curves.Scalar {
	pReduced := p.Mod(field.Order())
	s := field.Element().SetNat(pReduced)
	return s
}

func sampleJRange(prng io.Reader) (*saferith.Int, error) {
	// extra byte for sign
	const byteLen = cggmp21.ParamLPrime/8 + 1
	var data [byteLen]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample Int")
	}

	var result saferith.Int
	err = result.UnmarshalBinary(data[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample Int")
	}

	return &result, nil
}

func messageToScalar(cipherSuite types.SigningSuite, message []byte) (curves.Scalar, error) {
	messageHash, err := hashing.Hash(cipherSuite.Hash(), message)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash message")
	}
	mPrimeUint := ecdsa.BitsToInt(messageHash, cipherSuite.Curve())
	mPrime, err := cipherSuite.Curve().ScalarField().Element().SetBytes(mPrimeUint.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot convert message to scalar")
	}
	return mPrime, nil
}
