package redistribute

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 redistributes each previous shareholder's shares into subshares under the
// next access structure.
//
// Previous shareholders broadcast verification material for their previous share and the
// new subsharing, and privately send one subshare to each new shareholder. Parties
// that are not previous shareholders return nil outputs.
func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], network.OutgoingUnicasts[*Round1P2P[G, S], *Participant[G, S]], error) {
	if p.state.round != 1 {
		return nil, nil, ErrValidation.WithMessage("invalid round")
	}
	defer p.state.round.IncrementBy(1)

	if !p.isPrevShareholder(p.ctx.HolderID()) {
		return &Round1Broadcast[G, S]{}, nil, nil
	}

	prevShareholdersSubCtx, err := p.ctx.SubContext(p.prevShareholders)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create subcontext")
	}
	prevScheme, err := kw.NewInducedScheme(p.prevShard.MSP())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create sharing scheme")
	}
	prevQuorum, err := unanimity.NewUnanimityAccessStructure(prevShareholdersSubCtx.Quorum())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create unanimity quorum")
	}
	prevShare, err := prevScheme.ConvertShareToAdditive(p.prevShard.Share(), prevQuorum)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert previous share to additive")
	}
	zeroShare, err := przs.SampleZeroShare(prevShareholdersSubCtx, algebra.StructureMustBeAs[algebra.PrimeField[S]](prevShare.Value().Structure()))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample zero share")
	}
	prevShare = prevShare.Add(zeroShare)
	prevShareValue := prevShare.Value()

	pk, _ := p.prevShard.VerificationVector().Value().Get(0, 0)
	nextScheme, err := feldman.NewScheme(algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](pk.Structure()), p.nextAccessStructures)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create feldman scheme")
	}
	nextSubSharesOutput, err := nextScheme.Deal(kw.NewSecret(prevShareValue), p.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot deal with previous share")
	}

	r1b := &Round1Broadcast[G, S]{
		ShareVerificationVector:    p.prevShard.VerificationVector(),
		SubShareVerificationVector: nextSubSharesOutput.VerificationMaterial(),
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id := range p.nextAccessStructures.Shareholders().Iter() {
		subShare, ok := nextSubSharesOutput.Shares().Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("invalid sharing")
		}
		if id == p.ctx.HolderID() {
			p.state.share = subShare
			p.state.shareVerificationVector = p.prevShard.VerificationVector()
			p.state.subShareVerificationVector = nextSubSharesOutput.VerificationMaterial()
			continue
		}
		r1u.Put(id, &Round1P2P[G, S]{
			SubShare: subShare,
		})
	}

	return r1b, r1u.Freeze(), nil
}

// Round2 verifies all received subshares, aggregates them, and outputs the
// participant's redistributed shard.
//
// Only the previous shareholders produce an output shard. Parties outside the next access
// structure return nil.
func (p *Participant[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S], *Participant[G, S]], r1u network.RoundMessages[*Round1P2P[G, S], *Participant[G, S]]) (*mpc.BaseShard[G, S], error) {
	if p.state.round != 2 {
		return nil, ErrValidation.WithMessage("invalid round")
	}
	defer p.state.round.IncrementBy(1)

	if !p.isNextShareholder(p.ctx.HolderID()) {
		//nolint:nilnil // intentional
		return nil, nil
	}

	if errB := network.ValidateIncomingMessages(p, p.otherPrevShareholders(), r1b); errB != nil {
		return nil, errs.Wrap(errB).WithMessage("invalid broadcast input")
	}
	if errU := network.ValidateIncomingMessages(p, p.otherPrevShareholders(), r1u); errU != nil {
		return nil, errs.Wrap(errU).WithMessage("invalid p2p input")
	}

	for id := range p.otherPrevShareholders() {
		b, okb := r1b.Get(id)
		u, oku := r1u.Get(id)
		if !okb || !oku {
			return nil, ErrFailed.WithMessage("missing message")
		}
		pk, _ := b.SubShareVerificationVector.Value().Get(0, 0)
		nextScheme, err := feldman.NewScheme(algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](pk.Structure()), p.nextAccessStructures)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create feldman scheme")
		}

		// verify subshare
		if err := nextScheme.Verify(u.SubShare, b.SubShareVerificationVector); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify subshare")
		}
		if p.state.share == nil {
			p.state.share = u.SubShare
			p.state.subShareVerificationVector = b.SubShareVerificationVector
			p.state.shareVerificationVector = b.ShareVerificationVector
		} else {
			p.state.share = p.state.share.Add(u.SubShare)
			p.state.subShareVerificationVector = p.state.subShareVerificationVector.Op(b.SubShareVerificationVector)
			if !p.state.shareVerificationVector.Equal(b.ShareVerificationVector) {
				return nil, base.ErrAbort.WithMessage("share verification vectors do not match")
			}
		}
	}

	// verify share
	oldPk, _ := p.state.shareVerificationVector.Value().Get(0, 0)
	newPk, _ := p.state.subShareVerificationVector.Value().Get(0, 0)
	if !oldPk.Equal(newPk) {
		return nil, base.ErrAbort.WithMessage("inconsistent sharing")
	}
	nextScheme, err := feldman.NewScheme(algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](newPk.Structure()), p.nextAccessStructures)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create feldman scheme")
	}
	if err := nextScheme.Verify(p.state.share, p.state.subShareVerificationVector); err != nil {
		return nil, base.ErrAbort.WithMessage("inconsistent sharing")
	}

	newShard, err := mpc.NewBaseShard(p.state.share, p.state.subShareVerificationVector, nextScheme.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create a shard")
	}

	return newShard, nil
}
