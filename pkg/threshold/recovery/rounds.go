package recovery

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
	polynomialsUtils "github.com/copperexchange/krypton-primitives/pkg/base/polynomials/utils"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

type Round1Broadcast = hjky.Round1Broadcast
type Round1P2P = hjky.Round1P2P

type Round2P2P struct {
	BlindedPartiallyRecoveredShare curves.Scalar

	_ types.Incomparable
}

func (p *Participant) Round1() (*Round1Broadcast, map[types.IdentityHash]*Round1P2P, error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	// step 1.1
	round1broadcast, round1p2p, err := p.sampler.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute round 1 of zero share sampler")
	}
	p.round++
	return round1broadcast, round1p2p, nil
}

func (p *Participant) Round2(round1broadcast map[types.IdentityHash]*Round1Broadcast, round1p2p map[types.IdentityHash]*Round1P2P) (map[types.IdentityHash]*Round2P2P, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	// step 2.1
	sample, _, _, err := p.sampler.Round2(round1broadcast, round1p2p)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sample a zero share")
	}
	// step 2.2
	wrappedSample := &shamir.Share{
		Id:    p.GetSharingId(),
		Value: sample,
	}

	partiesOfAdditiveConversion := make([]int, len(p.sortedPresentRecoverersList)+1) // recoverers and lost party, all share samples of zero.
	lostPartySharingId := p.sampler.PedersenParty.IdentityHashToSharingId[p.lostPartyIdentityKey.Hash()]
	partiesOfAdditiveConversion[0] = lostPartySharingId
	for i := 0; i < len(p.sortedPresentRecoverersList); i++ {
		partiesOfAdditiveConversion[i+1] = p.sampler.PedersenParty.IdentityHashToSharingId[p.sortedPresentRecoverersList[i].Hash()] // 0'th identity is that of the lost party, hence indexing at i+1
	}
	p.additiveShareOfZero, err = wrappedSample.ToAdditive(partiesOfAdditiveConversion)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert sampled zero share to additive form")
	}
	if !p.IsRecoverer() {
		p.round++
		return nil, nil //nolint:nilnil // this is the correct behaviour.
	}

	curve := p.GetCohortConfig().CipherSuite.Curve

	// step 2.3.1
	lostPartySharingIdScalar := curve.ScalarField().New(uint64(lostPartySharingId))
	recovererSharingIdScalar := make([]curves.Scalar, len(p.sortedPresentRecoverersList))
	myIndex := -1
	for i, recovererSharingId := range partiesOfAdditiveConversion[1:] { // 0th index is the lost party
		recovererSharingIdScalar[i] = curve.ScalarField().New(uint64(recovererSharingId))
		if p.GetSharingId() == recovererSharingId {
			myIndex = i
		}
	}
	if myIndex == -1 {
		return nil, errs.NewMissing("could not find my lagrange basis index")
	}
	lx, err := polynomialsUtils.Li(polynomials.GetScalarUnivariatePolynomialsSet(curve.ScalarField()), myIndex, recovererSharingIdScalar)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute lagrange basis polynomial at x=%d", lostPartySharingId)
	}
	// step 2.3.2
	s := lx.Eval(lostPartySharingIdScalar).Mul(p.signingKeyShare.Share)
	// step 2.3.3
	sHat := s.Add(p.additiveShareOfZero)

	p.round = -1 // this is to prevent recoverer from running round 3.

	// step 2.3.4
	return map[types.IdentityHash]*Round2P2P{
		p.lostPartyIdentityKey.Hash(): {
			BlindedPartiallyRecoveredShare: sHat,
		},
	}, nil
}

func (p *Participant) Round3(round2output map[types.IdentityHash]*Round2P2P) (*tsignatures.SigningKeyShare, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	// step 3.1
	res := p.additiveShareOfZero // this, added to all blinded share, will all cancel out to zero
	for _, recoverer := range p.sortedPresentRecoverersList {
		receivedMessage, exists := round2output[recoverer.Hash()]
		if !exists {
			return nil, errs.NewMissing("did not receive a message from %x", recoverer.Hash())
		}
		if receivedMessage.BlindedPartiallyRecoveredShare == nil {
			return nil, errs.NewIsNil("blinded partially recovered share of recoverer %x is nil", recoverer.Hash())
		}
		res = res.Add(receivedMessage.BlindedPartiallyRecoveredShare)
	}
	// step 3.2
	if !p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(res).Equal(p.publicKeyShares.SharesMap[p.lostPartyIdentityKey.Hash()]) {
		return nil, errs.NewTotalAbort(nil, "recovered partial key is incompatible")
	}

	// step 3.3
	p.round++
	return &tsignatures.SigningKeyShare{
		Share:     res,
		PublicKey: p.publicKeyShares.PublicKey,
	}, nil
}
