package hjky

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
)

func (p *Participant) Round1() (r1bo *Round1Broadcast, r1uo network.RoundMessages[types.ThresholdProtocol, *Round1P2P], err error) {
	shares, verification, err := p.State.feldmanScheme.DealVerifiable(p.Protocol.Curve().ScalarField().Zero(), p.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to share zero")
	}
	p.State.feldmanVerification = verification

	r1bo = &Round1Broadcast{FeldmanVerification: verification}
	r1uo = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.feldmanShare = shares[sharingId]
		} else {
			r1uo.Put(identityKey, &Round1P2P{FeldmanShare: shares[sharingId]})
		}
	}

	return r1bo, r1uo, nil
}

func (p *Participant) Round2(
	r2bi network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast],
	r2ui network.RoundMessages[types.ThresholdProtocol, *Round1P2P],
) (share curves.Scalar, publicKeySharesMap ds.Map[types.SharingID, curves.Point], feldmanCommitmentVector []curves.Point, err error) {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		bIn, _ := r2bi.Get(identityKey)
		uIn, _ := r2ui.Get(identityKey)
		if err := p.State.feldmanScheme.VerifyShare(uIn.FeldmanShare, bIn.FeldmanVerification); err != nil || !bIn.FeldmanVerification[0].IsAdditiveIdentity() {
			return nil, nil, nil, errs.NewIdentifiableAbort(identityKey.String(), "invalid share")
		}

		p.State.feldmanShare = p.State.feldmanScheme.ShareAdd(p.State.feldmanShare, uIn.FeldmanShare)
		p.State.feldmanVerification = p.State.feldmanScheme.VerificationAdd(p.State.feldmanVerification, bIn.FeldmanVerification)
	}

	publicKeySharesMap = hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId := range p.SharingCfg.Iter() {
		publicKeySharesMap.Put(sharingId, polynomials.EvalInExponent(p.State.feldmanVerification, sharingId.ToScalar(p.Protocol.Curve().ScalarField())))
	}

	return p.State.feldmanShare.Value, publicKeySharesMap, p.State.feldmanVerification, nil
}
