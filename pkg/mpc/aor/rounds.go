package aor

import (
	"crypto/subtle"
	"encoding/binary"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 samples a random value, commits to it, and broadcasts the commitment.
func (p *Participant) Round1() (*Round1Broadcast, error) {
	// validation
	if p.round != 1 {
		return nil, ErrRound.WithMessage("expected round 1, got %d", p.round)
	}

	// step 1.1: sample a random message
	p.state.r = make([]byte, p.size)
	_, err := io.ReadFull(p.prng, p.state.r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample random message")
	}

	// step 1.2: commit your sample
	p.state.rCommitments = make(map[sharing.ID]hashcom.Commitment)
	p.state.rCommitments[p.id], p.state.rWitness, err = commitments.Commit(p.commitmentKey, p.state.r, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not commit to the seed")
	}

	// step 1.3: broadcast your commitment
	p.round++
	return &Round1Broadcast{
		Commitment: p.state.rCommitments[p.id],
	}, nil
}

// Round2 records all commitments and broadcasts the local opening (message, witness).
func (p *Participant) Round2(r1 network.RoundMessages[*Round1Broadcast, *Participant]) (*Round2Broadcast, error) {
	// validation
	incomingMessages, err := validateIncomingBroadcastMessages(p, 2, r1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming messages or round mismatch")
	}

	// step 2.0: store all commitments
	for id, m := range incomingMessages {
		p.state.rCommitments[id] = m.Commitment
	}
	p.writeCommitmentsToTranscript()

	// step 2.1: broadcast your witness and your sample r_i
	p.round++
	return &Round2Broadcast{
		Message: p.state.r,
		Witness: p.state.rWitness,
	}, nil
}

// Round3 verifies all openings and aggregates the agreed random output.
func (p *Participant) Round3(r2 network.RoundMessages[*Round2Broadcast, *Participant]) ([]byte, error) {
	// validation
	incomingMessages, err := validateIncomingBroadcastMessages(p, 3, r2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming messages or round mismatch")
	}

	r := p.state.r
	for id, m := range incomingMessages {
		if err := p.commitmentKey.Open(p.state.rCommitments[id], m.Message, m.Witness); err != nil {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("could not verify commitment")
		}
		subtle.XORBytes(r, r, m.Message)
	}

	p.round++
	return r, nil
}

func (p *Participant) writeCommitmentsToTranscript() {
	for _, id := range slices.Sorted(p.quorum.Iter()) {
		cid := p.state.rCommitments[id]
		p.tape.AppendBytes(commitmentLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), cid[:])
	}
}
