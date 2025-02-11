package recovery

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

func (p *Recoverer) Round1() (r1bo *Round1Broadcast, err error) {
	blind, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample blind")
	}

	blindShares, blindVerification, err := p.State.feldmanScheme.DealVerifiable(blind, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal blind")
	}

	shift := blindShares[p.MislayerSharingId].Value
	blindVerification = p.State.feldmanScheme.VerificationSubValue(blindVerification, shift)
	for sharingId, share := range blindShares {
		blindShares[sharingId] = p.State.feldmanScheme.ShareSubValue(share, shift)
	}
	p.RecovererState.blindShares = blindShares

	r1bo = &Round1Broadcast{FeldmanVerification: blindVerification}
	return r1bo, nil
}

func (p *Recoverer) Round2(r2bi network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast]) (r2uo network.RoundMessages[types.ThresholdProtocol, *Round2P2P], err error) {
	p.RecovererState.blindVerifications = make(map[types.SharingID][]curves.Point)
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId || !p.RecoverersIdentityKeys.Contains(identityKey) {
			continue
		}

		inB, _ := r2bi.Get(identityKey)
		p.RecovererState.blindVerifications[sharingId] = inB.FeldmanVerification
		if !polynomials.EvalInExponent(p.RecovererState.blindVerifications[sharingId], p.MislayerSharingId.ToScalar(p.Protocol.Curve().ScalarField())).IsAdditiveIdentity() {
			return nil, errs.NewIdentifiableAbort(sharingId, "invalid verification")
		}
	}

	r2uo = network.NewRoundMessages[types.ThresholdProtocol, *Round2P2P]()
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId || !p.RecoverersIdentityKeys.Contains(identityKey) {
			continue
		}

		r2uo.Put(identityKey, &Round2P2P{FeldmanShare: p.RecovererState.blindShares[sharingId]})
	}

	return r2uo, nil
}

func (p *Recoverer) Round3(r3ui network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (r3bo *Round3Broadcast, r3uo network.RoundMessages[types.ThresholdProtocol, *Round3P2P], err error) {
	signingShare := &feldman_vss.Share{
		Id:    p.MySharingId,
		Value: p.MySigningKeyShare.Share,
	}
	blindShare := p.State.feldmanScheme.ShareAdd(signingShare, p.RecovererState.blindShares[p.MySharingId])

	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId || !p.RecoverersIdentityKeys.Contains(identityKey) {
			continue
		}

		inU, _ := r3ui.Get(identityKey)
		share := inU.FeldmanShare
		if err := p.State.feldmanScheme.VerifyShare(share, p.RecovererState.blindVerifications[sharingId]); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, sharingId, "invalid share")
		}
		blindShare = p.State.feldmanScheme.ShareAdd(blindShare, share)
	}

	r3bo = &Round3Broadcast{FeldmanVerification: p.MyPartialPublicKeys.FeldmanCommitmentVector}
	r3uo = network.NewRoundMessages[types.ThresholdProtocol, *Round3P2P]()
	r3uo.Put(p.MislayerIdentityKey, &Round3P2P{BlindFeldmanShare: blindShare})

	return r3bo, r3uo, nil
}

func (p *Recoverer) Round4(r4bi network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast]) (err error) {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId || !p.RecoverersIdentityKeys.Contains(identityKey) {
			continue
		}

		inB, _ := r4bi.Get(identityKey)
		if len(inB.FeldmanVerification) != len(p.MyPartialPublicKeys.FeldmanCommitmentVector) {
			return errs.NewIdentifiableAbort(sharingId, "invalid feldman vector")
		}
		for i, l := range p.MyPartialPublicKeys.FeldmanCommitmentVector {
			r := inB.FeldmanVerification[i]
			if !l.Equal(r) {
				return errs.NewIdentifiableAbort(sharingId, "invalid feldman vector")
			}
		}
	}

	return nil
}

func (p *Mislayer) Round4(r4bi network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast], r4ui network.RoundMessages[types.ThresholdProtocol, *Round3P2P]) (sks *tsignatures.SigningKeyShare, ppk *tsignatures.PartialPublicKeys, err error) {
	xs := make([]curves.Scalar, 0, p.RecoverersIdentityKeys.Size())
	ys := make([]curves.Scalar, 0, p.RecoverersIdentityKeys.Size())

	var verification []curves.Point
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId || !p.RecoverersIdentityKeys.Contains(identityKey) {
			continue
		}

		inU, _ := r4ui.Get(identityKey)
		xs = append(xs, sharingId.ToScalar(p.Protocol.Curve().ScalarField()))
		ys = append(ys, inU.BlindFeldmanShare.Value)

		inB, _ := r4bi.Get(identityKey)
		if verification == nil {
			verification = inB.FeldmanVerification
		} else {
			if len(verification) != len(inB.FeldmanVerification) {
				return nil, nil, errs.NewFailed("invalid verification")
			}
			for i, l := range verification {
				r := inB.FeldmanVerification[i]
				if !l.Equal(r) {
					return nil, nil, errs.NewFailed("invalid verification")
				}
			}
		}
	}

	recoveredShare, err := lagrange.Interpolate(p.Protocol.Curve(), xs, ys, p.MySharingId.ToScalar(p.Protocol.Curve().ScalarField()))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot interpolate recovered share")
	}
	recoveredFeldmanShare := &feldman_vss.Share{
		Id:    p.MySharingId,
		Value: recoveredShare,
	}
	err = p.State.feldmanScheme.VerifyShare(recoveredFeldmanShare, verification)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "invalid recovered share")
	}

	recoveredPublicKey := verification[0]
	recoveredPartialPublicKeys := hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId := range p.SharingCfg.Iter() {
		recoveredPartialPublicKeys.Put(sharingId, polynomials.EvalInExponent(verification, sharingId.ToScalar(p.Protocol.Curve().ScalarField())))
	}

	sks = &tsignatures.SigningKeyShare{
		Share:     recoveredShare,
		PublicKey: recoveredPublicKey,
	}
	pks := &tsignatures.PartialPublicKeys{
		PublicKey:               recoveredPublicKey,
		Shares:                  recoveredPartialPublicKeys,
		FeldmanCommitmentVector: verification,
	}

	return sks, pks, nil
}
