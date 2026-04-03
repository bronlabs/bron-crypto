package canetti

import (
	"crypto/subtle"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
)

// Round1 samples the local dealer contribution, commits to its opening
// material, and returns the round 1 broadcast.
func (p *Participant[G, S]) Round1() (*Round1Broadcast[G, S], error) {
	if p.round != 1 {
		return nil, ErrRound.WithMessage("actual=%d, expected=%d", p.round, 1)
	}

	dealerOutput, _, dealerFunc, err := p.sharingScheme.DealRandomAndRevealDealerFunc(p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot deal random field element")
	}

	rho := make([]byte, p.rhoLen)
	_, err = io.ReadFull(p.prng, rho)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample rho")
	}

	schStatement := batch_schnorr.NewStatement(p.group.Generator(), slices.Collect(dealerOutput.VerificationMaterial().Value().Iter())...)
	schWitness := batch_schnorr.NewWitness(slices.Collect(dealerFunc.RandomColumn().Iter())...)
	bigA, tau, err := zkCom(p.schScheme, schStatement, schWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("prove commitment failed")
	}

	msg := &CommitmentMessage[G, S]{
		SessionID: p.ctx.SessionID(),
		SharingID: p.ctx.HolderID(),
		Rho:       rho,
		X:         dealerOutput.VerificationMaterial(),
		A:         bigA,
	}

	bigV, u, err := p.commit(msg)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment")
	}

	p.round.IncrementBy(1)
	p.state.dealerFunc = dealerFunc
	p.state.verificationVector = dealerOutput.VerificationMaterial()
	p.state.rho = rho
	p.state.tau = tau
	p.state.u = u
	p.state.msg = make(map[sharing.ID]*CommitmentMessage[G, S])
	p.state.msg[p.ctx.HolderID()] = msg
	r1b := &Round1Broadcast[G, S]{
		V: bigV,
	}
	return r1b, nil
}

// Round2 opens the sender's commitment and privately distributes dealer shares
// to the other parties.
func (p *Participant[G, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[G, S], *Participant[G, S]]) (*Round2Broadcast[G, S], network.OutgoingUnicasts[*Round2P2P[G, S], *Participant[G, S]], error) {
	if p.round != 2 {
		return nil, nil, ErrRound.WithMessage("actual=%d, expected=%d", p.round, 2)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r1b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid incoming messages")
	}

	vs := make(map[sharing.ID]hash_comm.Commitment)
	for id := range p.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(id)
		vs[id] = b.V
	}

	r2b := &Round2Broadcast[G, S]{
		Message: p.state.msg[p.ctx.HolderID()],
		U:       p.state.u,
	}
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[G, S]]()
	for id := range p.ctx.OtherPartiesOrdered() {
		share, _ := p.state.dealerFunc.ShareOf(id)
		r2u.Put(id, &Round2P2P[G, S]{
			Share: share,
		})
	}

	p.round.IncrementBy(1)
	p.state.vs = vs
	return r2b, r2u.Freeze(), nil
}

// Round3 verifies incoming openings and shares, aggregates all dealer
// contributions, and returns the local batch Schnorr response.
func (p *Participant[G, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[G, S], *Participant[G, S]], r2u network.RoundMessages[*Round2P2P[G, S], *Participant[G, S]]) (*Round3Broadcast[G, S], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("actual=%d, expected=%d", p.round, 3)
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2b); errB != nil {
		return nil, errs.Wrap(errB).WithMessage("invalid incoming broadcast messages")
	}
	if errU := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2u); errU != nil {
		return nil, errs.Wrap(errU).WithMessage("invalid incoming unicast messages")
	}

	share, err := p.state.dealerFunc.ShareOf(p.ctx.HolderID())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get share")
	}

	for id := range p.ctx.OtherPartiesOrdered() {
		b, _ := r2b.Get(id)
		u, _ := r2u.Get(id)

		if err := p.verify(b.Message, p.state.vs[id], b.U); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment")
		}
		if b.Message.SessionID != p.ctx.SessionID() {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid message")
		}
		if b.Message.SharingID != id {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid message")
		}
		if err := p.sharingScheme.Verify(u.Share, b.Message.X); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid share")
		}
		if p.rhoLen != len(b.Message.Rho) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid rho")
		}

		subtle.XORBytes(p.state.rho, p.state.rho, b.Message.Rho)
		p.state.verificationVector = p.state.verificationVector.Op(b.Message.X)
		share = share.Op(u.Share)
		p.state.msg[id] = b.Message
	}

	schStatement := batch_schnorr.NewStatement(p.group.Generator(), slices.Collect(p.state.msg[p.ctx.HolderID()].X.Value().Iter())...)
	schWitness := batch_schnorr.NewWitness(slices.Collect(p.state.dealerFunc.RandomColumn().Iter())...)
	schAux := newAux(p.ctx.SessionID(), p.ctx.HolderID(), p.state.rho)
	psi, err := zkProve(p.schScheme, schStatement, schWitness, p.state.msg[p.ctx.HolderID()].A, p.state.tau, schAux)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove")
	}

	r3b := &Round3Broadcast[G, S]{
		Psi: psi,
	}
	p.round.IncrementBy(1)
	p.state.share = share
	return r3b, nil
}

// Round4 verifies the other parties' proofs and returns the final aggregated
// shard for the configured access structure.
func (p *Participant[G, S]) Round4(r3b network.RoundMessages[*Round3Broadcast[G, S], *Participant[G, S]]) (*mpc.BaseShard[G, S], error) {
	if p.round != 4 {
		return nil, ErrRound.WithMessage("actual=%d, expected=%d", p.round, 4)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r3b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming messages")
	}

	for id := range p.ctx.OtherPartiesOrdered() {
		b, _ := r3b.Get(id)
		schStatement := batch_schnorr.NewStatement(p.group.Generator(), slices.Collect(p.state.msg[id].X.Value().Iter())...)
		schAux := newAux(p.ctx.SessionID(), id, p.state.rho)
		if err := zkVrfy(p.schScheme, schStatement, schAux, b.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid proof")
		}
	}

	shard, err := mpc.NewBaseShard(p.state.share, p.state.verificationVector, p.sharingScheme.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create shard")
	}
	p.round.IncrementBy(1)
	return shard, nil
}
