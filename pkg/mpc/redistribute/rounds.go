package redistribute

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 starts the HJKY zero-sharing subprotocol among previous shareholders
// and returns the resulting public broadcast plus per-recipient private
// round-1 messages.
//
// Parties that are not previous shareholders return an empty broadcast and no
// unicasts.
func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S], *Participant[G, S]], error) {
	if p.state.round != 1 {
		return nil, nil, ErrValidation.WithMessage("invalid round")
	}
	defer p.state.round.IncrementBy(1)

	if !p.isPrevShareholder(p.ctx.HolderID()) {
		return &Round1Broadcast[G, S]{}, nil, nil
	}

	zeroR1b, zeroR1U, err := p.zeroParticipant.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run round 1 of HJKY")
	}

	r1b := &Round1Broadcast[G, S]{
		ZeroR1: zeroR1b,
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id := range p.otherPrevShareholders() {
		m, ok := zeroR1U.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		r1u.Put(id, &Round1P2P[G, S]{
			ZeroR1: m,
		})
	}

	return r1b, r1u.Freeze(), nil
}

// Round2 completes the HJKY zero-sharing subprotocol for previous
// shareholders, converts each previous shard into an additive contribution,
// re-shares that contribution under the next access structure, and returns the
// resulting public metadata plus per-recipient private share contributions.
//
// Parties that are not previous shareholders return an empty broadcast and no
// unicasts.
func (p *Participant[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S], *Participant[G, S]], r1u network.RoundMessages[*Round1P2P[G, S], *Participant[G, S]]) (*Round2Broadcast[G, S], network.OutgoingUnicasts[*Round2P2P[G, S], *Participant[G, S]], error) {
	if p.state.round != 2 {
		return nil, nil, ErrValidation.WithMessage("invalid round")
	}
	defer p.state.round.IncrementBy(1)

	if !p.isPrevShareholder(p.ctx.HolderID()) {
		return &Round2Broadcast[G, S]{}, nil, nil
	}
	if err := network.ValidateIncomingMessages(p, p.otherPrevShareholders(), r1b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(p, p.otherPrevShareholders(), r1u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	zeroR1b := hashmap.NewComparable[sharing.ID, *hjky.Round1Broadcast[G, S]]()
	zeroR1u := hashmap.NewComparable[sharing.ID, *hjky.Round1P2P[G, S]]()
	for id := range p.otherPrevShareholders() {
		mb, ok := r1b.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		mu, ok := r1u.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing message")
		}
		zeroR1b.Put(id, mb.ZeroR1)
		zeroR1u.Put(id, mu.ZeroR1)
	}

	zeroShare, zeroVerificationVector, err := p.zeroParticipant.Round2(zeroR1b.Freeze(), zeroR1u.Freeze())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run round 2 of HJKY")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](p.prevShard.PublicKeyValue().Structure())
	prevSharingScheme, err := p.mspSharingScheme(group, p.prevShard.MSP())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create KW sharing scheme")
	}
	prevAdditiveShare, err := prevSharingScheme.ConvertShareToAdditive(p.prevShard.Share(), p.prevUnanimity)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert previous share to additive")
	}

	zeroSharingScheme, err := p.acSharingScheme(group, p.prevUnanimity)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create feldman sharing scheme")
	}
	shift, err := zeroSharingScheme.ConvertShareToAdditive(zeroShare, p.prevUnanimity)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute shift")
	}
	additiveContribution := prevAdditiveShare.Add(shift).Value()

	nextSharingScheme, err := p.acSharingScheme(group, p.nextAccessStructures)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create feldman sharing scheme")
	}
	nextOutput, err := nextSharingScheme.Deal(kw.NewSecret(additiveContribution), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot deal with previous share")
	}
	nextShareContributions, nextVerificationVectorContribution := nextOutput.Shares(), nextOutput.VerificationMaterial()

	p.state.zeroVerificationVector = zeroVerificationVector
	r2b := &Round2Broadcast[G, S]{
		PrevMSP:                            p.prevShard.MSP(),
		PrevVerificationVector:             p.prevShard.VerificationVector(),
		ZeroVerificationVector:             zeroVerificationVector,
		NextVerificationVectorContribution: nextVerificationVectorContribution,
	}
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[G, S]]()
	for id := range p.nextAccessStructures.Shareholders().Iter() {
		nextShare, ok := nextShareContributions.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("invalid sharing")
		}
		if id == p.ctx.HolderID() {
			p.state.share = nextShare
			p.state.shareVerificationVector = nextVerificationVectorContribution
			continue
		}
		r2u.Put(id, &Round2P2P[G, S]{NextShareContribution: nextShare})
	}
	return r2b, r2u.Freeze(), nil
}

// Round3 verifies and aggregates all round-2 contributions addressed to the
// local next shareholder and returns the resulting redistributed shard.
//
// Parties that are not next shareholders return nil.
func (p *Participant[G, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[G, S], *Participant[G, S]], r2u network.RoundMessages[*Round2P2P[G, S], *Participant[G, S]]) (*mpc.BaseShard[G, S], error) {
	if p.state.round != 3 {
		return nil, ErrValidation.WithMessage("invalid round")
	}
	defer p.state.round.IncrementBy(1)

	if !p.isNextShareholder(p.ctx.HolderID()) {
		return nil, nil //nolint:nilnil // intentional
	}
	if err := network.ValidateIncomingMessages(p, p.otherPrevShareholders(), r2b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(p, p.otherPrevShareholders(), r2u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	var err error
	for id := range p.otherPrevShareholders() {
		b, ok := r2b.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		u, ok := r2u.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}

		if p.state.share == nil {
			p.state.share = u.NextShareContribution
		} else {
			p.state.share = p.state.share.Add(u.NextShareContribution)
		}
		if p.state.shareVerificationVector == nil {
			p.state.shareVerificationVector = b.NextVerificationVectorContribution
		} else {
			p.state.shareVerificationVector, err = p.state.shareVerificationVector.Op(b.NextVerificationVectorContribution)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot combine verification vectors")
			}
		}
	}
	newPk, err := p.state.shareVerificationVector.Value().Get(0, 0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get public key")
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](newPk.Structure())
	nextScheme, err := p.acSharingScheme(group, p.nextAccessStructures)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create feldman scheme")
	}
	for id := range p.otherPrevShareholders() {
		b, ok := r2b.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		u, ok := r2u.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		if err := nextScheme.Verify(u.NextShareContribution, b.NextVerificationVectorContribution); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid share")
		}
	}

	// make identifiable verification if possible
	var trustedMSP *msp.MSP[S]
	var trustedVerificationVector *feldman.VerificationVector[G, S]
	var trustedZeroVerificationVector *feldman.VerificationVector[G, S]
	if p.isPrevShareholder(p.ctx.HolderID()) {
		trustedMSP = p.prevShard.MSP()
		trustedVerificationVector = p.prevShard.VerificationVector()
		trustedZeroVerificationVector = p.state.zeroVerificationVector
	} else if p.trustedAnchorID != 0 {
		b, ok := r2b.Get(p.trustedAnchorID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		trustedMSP = b.PrevMSP
		trustedVerificationVector = b.PrevVerificationVector
		trustedZeroVerificationVector = b.ZeroVerificationVector
	}
	if trustedMSP != nil {
		prevScheme, err := p.mspSharingScheme(group, trustedMSP)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create KW sharing scheme")
		}
		prevLiftedDealerFunc, err := feldman.NewLiftedDealerFunc(trustedVerificationVector, trustedMSP)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create lifted dealer function")
		}

		zeroScheme, err := p.acSharingScheme(group, p.prevUnanimity)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create feldman sharing scheme")
		}
		zeroLiftedDealerFunc, err := feldman.NewLiftedDealerFunc(trustedZeroVerificationVector, zeroScheme.MSP())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create lifted dealer function")
		}

		// check consistency of verification vectors
		for id := range p.otherPrevShareholders() {
			b, ok := r2b.Get(id)
			if !ok {
				return nil, ErrFailed.WithMessage("missing message")
			}

			if !b.PrevMSP.Equal(trustedMSP) || !b.PrevVerificationVector.Equal(trustedVerificationVector) || !b.ZeroVerificationVector.Equal(trustedZeroVerificationVector) {
				return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("inconsistent verification vectors")
			}

			prevLiftedShare, err := prevLiftedDealerFunc.ShareOf(id)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot compute previous share")
			}
			prevLiftedAdditiveShare, err := prevScheme.ConvertLiftedShareToAdditive(prevLiftedShare, p.prevUnanimity)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot convert previous share to additive")
			}
			zeroLiftedShare, err := zeroLiftedDealerFunc.ShareOf(id)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot compute zero share")
			}
			liftedShift, err := zeroScheme.ConvertLiftedShareToAdditive(zeroLiftedShare, p.prevUnanimity)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot compute shift")
			}

			expectedPartialPk := prevLiftedAdditiveShare.Add(liftedShift).Value()
			actualPartialPk, err := b.NextVerificationVectorContribution.Value().Get(0, 0)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot get partial public key")
			}
			if !actualPartialPk.Equal(expectedPartialPk) {
				return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid verification vector contribution")
			}
		}
	}

	// This below should never fail if all per-sender checks above are correct.
	// Keep the aggregate check anyway (if anchor not provided) and as a final
	// sanity check before returning a shard to the caller.
	for id := range p.otherPrevShareholders() {
		b, ok := r2b.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message")
		}
		oldPk, err := b.PrevVerificationVector.Value().Get(0, 0)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot get previous public key")
		}
		if !oldPk.Equal(newPk) {
			return nil, base.ErrAbort.WithMessage("inconsistent previous verification vector")
		}
	}
	if err := nextScheme.Verify(p.state.share, p.state.shareVerificationVector); err != nil {
		return nil, base.ErrAbort.WithMessage("inconsistent aggregated share")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	nextMspMatrix, err := accessstructures.InducedMSP(field, p.nextAccessStructures)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get MSP")
	}
	nextBaseShard, err := mpc.NewBaseShard(p.state.share, p.state.shareVerificationVector, nextMspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create base shard")
	}
	return nextBaseShard, nil
}
