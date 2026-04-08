package hjky

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 deals a zero-sharing and distributes shares and verification vectors.
func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S], *Participant[G, S]], error) {
	if p.round != 1 {
		return nil, nil, ErrRound.WithMessage("expected round 1")
	}

	dealerOut, err := p.scheme.Deal(kw.NewSecret(p.field.Zero()), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	p.state.verificationVectors = make(map[sharing.ID]feldman.VerificationVector[G, S])
	p.state.verificationVectors[p.ctx.HolderID()] = dealerOut.VerificationMaterial()

	var ok bool
	p.state.share, ok = dealerOut.Shares().Get(p.ctx.HolderID())
	if !ok {
		return nil, nil, ErrFailed.WithMessage("missing share")
	}

	r1b := &Round1Broadcast[G, S]{
		VerificationVector: p.state.verificationVectors[p.ctx.HolderID()],
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id := range p.ctx.OtherPartiesOrdered() {
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
func (p *Participant[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S], *Participant[G, S]], r1u network.RoundMessages[*Round1P2P[G, S], *Participant[G, S]]) (share *feldman.Share[S], verification feldman.VerificationVector[G, S], err error) {
	if p.round != 2 {
		return nil, nil, ErrRound.WithMessage("expected round 2")
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r1b); errB != nil {
		return nil, nil, errs.Wrap(errB)
	}
	if errU := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r1u); errU != nil {
		return nil, nil, errs.Wrap(errU)
	}

	share = p.state.share
	verificationVector := p.state.verificationVectors[p.ctx.HolderID()]
	for id := range p.ctx.OtherPartiesOrdered() {
		b, ok := r1b.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		u, ok := r1u.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}

		if err := p.scheme.Verify(u.ZeroShare, b.VerificationVector); err != nil {
			return nil, nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("share verification failed: %v", err)
		}
		pk, _ := b.VerificationVector.Value().Get(0, 0)
		if !pk.Equal(p.group.OpIdentity()) {
			return nil, nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("verification vector does not commit to zero")
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
		v := p.state.verificationVectors[id].Value()
		for c := range v.Iter() {
			p.ctx.Transcript().AppendBytes(coefficientLabel, c.Bytes())
		}
	}
}
