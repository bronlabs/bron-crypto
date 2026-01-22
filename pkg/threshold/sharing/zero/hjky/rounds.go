package hjky

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/errs-go/errs"
)

// Round1 deals a zero-sharing and distributes shares and verification vectors.
func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S]], error) {
	if p.round != 1 {
		return nil, nil, ErrRound.WithMessage("expected round 1")
	}

	dealerOut, err := p.scheme.Deal(feldman.NewSecret(p.field.Zero()), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	p.state.verificationVectors = make(map[sharing.ID]feldman.VerificationVector[G, S])
	p.state.verificationVectors[p.sharingID] = dealerOut.VerificationMaterial()

	var ok bool
	p.state.share, ok = dealerOut.Shares().Get(p.sharingID)
	if !ok {
		return nil, nil, ErrFailed.WithMessage("missing share")
	}

	r1b := &Round1Broadcast[G, S]{
		VerificationVector: p.state.verificationVectors[p.sharingID],
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id := range p.accessStructure.Shareholders().Iter() {
		if id == p.sharingID {
			continue
		}
		share, ok := dealerOut.Shares().Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing share")
		}
		r1u.Put(id, &Round1P2P[G, S]{
			ZeroShare: share,
		})
	}

	p.round++
	return r1b, r1u.Freeze(), nil
}

// Round2 verifies all zero-shares and aggregates them into a single zero-share and verification vector.
func (p *Participant[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S]], r1u network.RoundMessages[*Round1P2P[G, S]]) (share *feldman.Share[S], verification feldman.VerificationVector[G, S], err error) {
	if p.round != 2 {
		return nil, nil, ErrRound.WithMessage("expected round 2")
	}

	share = p.state.share
	verificationVector := p.state.verificationVectors[p.sharingID]
	for id := range p.accessStructure.Shareholders().Iter() {
		if id == p.sharingID {
			continue
		}
		b, ok := r1b.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		u, ok := r1u.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}

		if !b.VerificationVector.Coefficients()[0].Equal(p.group.OpIdentity()) || p.scheme.Verify(u.ZeroShare, b.VerificationVector) != nil {
			return nil, nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid share")
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
