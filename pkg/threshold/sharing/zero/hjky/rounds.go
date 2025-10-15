package hjky

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S]], error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("expected round 1")
	}

	dealerOut, err := p.scheme.Deal(feldman.NewSecret(p.field.Zero()), p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal shares")
	}
	p.state.verificationVectors = make(map[sharing.ID]feldman.VerificationVector[G, S])
	p.state.verificationVectors[p.sharingId] = dealerOut.VerificationMaterial()

	var ok bool
	p.state.share, ok = dealerOut.Shares().Get(p.sharingId)
	if !ok {
		return nil, nil, errs.NewFailed("missing share")
	}

	r1b := &Round1Broadcast[G, S]{
		VerificationVector: p.state.verificationVectors[p.sharingId],
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id := range p.accessStructure.Shareholders().Iter() {
		if id == p.sharingId {
			continue
		}
		share, ok := dealerOut.Shares().Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("missing share")
		}
		r1u.Put(id, &Round1P2P[G, S]{
			ZeroShare: share,
		})
	}

	p.round++
	return r1b, r1u.Freeze(), nil
}

func (p *Participant[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S]], r1u network.RoundMessages[*Round1P2P[G, S]]) (*feldman.Share[S], feldman.VerificationVector[G, S], error) {
	if p.round != 2 {
		return nil, nil, errs.NewRound("expected round 2")
	}

	share := p.state.share
	verificationVector := p.state.verificationVectors[p.sharingId]
	for id := range p.accessStructure.Shareholders().Iter() {
		if id == p.sharingId {
			continue
		}
		b, ok := r1b.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("missing message")
		}
		u, ok := r1u.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("missing message")
		}

		if !b.VerificationVector.Coefficients()[0].Equal(p.group.OpIdentity()) || p.scheme.Verify(u.ZeroShare, b.VerificationVector) != nil {
			return nil, nil, errs.NewIdentifiableAbort(id, "invalid share")
		}
		share = share.Add(u.ZeroShare)
		verificationVector = verificationVector.Op(b.VerificationVector)
		p.state.verificationVectors[id] = b.VerificationVector
	}
	p.writeVerificationVectorToTranscript()

	p.round++
	return share, verificationVector, nil
}

func (p *Participant[G, S]) writeVerificationVectorToTranscript() {
	for _, id := range slices.Sorted(maps.Keys(p.state.verificationVectors)) {
		v := p.state.verificationVectors[id]
		for _, c := range v.Coefficients() {
			p.tape.AppendBytes(coefficientLabel, c.Bytes())
		}
	}
}
