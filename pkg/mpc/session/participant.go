package session

import (
	"bytes"
	"encoding/binary"
	"io"
	"iter"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

const (
	sessionDomainSeparator = "BRON_CRYPTO_SESSION-SESSION"
	seedDomainSeparator    = "BRON_CRYPTO_SESSION-SEED"
)

var commonCommitmentKey = hash_comm.Key{
	'B', 'R', 'O', 'N', '_', 'C', 'R', 'Y', 'P', 'T', 'O', '_', 'N', 'O', 'T', 'H',
	'I', 'N', 'G', '_', 'U', 'P', '_', 'M', 'Y', '_', 'S', 'L', 'E', 'E', 'V', 'E',
}

// Participant runs the session seed setup protocol.
type Participant struct {
	id           sharing.ID
	sortedQuorum []sharing.ID
	prng         io.Reader
	round        int

	commonCommitter               *hash_comm.Committer
	commonVerifier                *hash_comm.Verifier
	commonContributionCommitments map[sharing.ID]hash_comm.Commitment
	commonContributions           map[sharing.ID][base.CollisionResistanceBytesCeil]byte
	commonContributionWitnesses   map[sharing.ID]hash_comm.Witness

	commitmentKeys                  map[sharing.ID]hash_comm.Key
	pairwiseContributionCommitments map[sharing.ID]hash_comm.Commitment
	pairwiseContributions           map[sharing.ID][base.CollisionResistanceBytesCeil]byte
	pairwiseContributionWitnesses   map[sharing.ID]hash_comm.Witness
}

// NewParticipant creates a participant bound to a quorum and PRNG.
func NewParticipant(id sharing.ID, quorum network.Quorum, prng io.Reader) (*Participant, error) {
	if quorum == nil {
		return nil, ErrInvalidArgument.WithMessage("quorum cannot be nil")
	}
	if quorum.Size() < 2 {
		return nil, ErrInvalidArgument.WithMessage("quorum size must be at least 2")
	}
	if id < 1 {
		return nil, ErrInvalidArgument.WithMessage("id must be non-zero")
	}
	if !quorum.Contains(id) {
		return nil, ErrInvalidArgument.WithMessage("id not in quorum")
	}
	if prng == nil {
		return nil, ErrInvalidArgument.WithMessage("prng cannot be nil")
	}

	sortedQuorum := slices.Collect(quorum.Iter())
	slices.Sort(sortedQuorum)

	commonCommitmentScheme, err := hash_comm.NewScheme(commonCommitmentKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create common commitment scheme")
	}
	commonCommitter, err := commonCommitmentScheme.Committer()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create common committer")
	}
	commonVerifier, err := commonCommitmentScheme.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create common verifier")
	}

	p := &Participant{
		id:              id,
		sortedQuorum:    sortedQuorum,
		prng:            prng,
		round:           1,
		commonCommitter: commonCommitter,
		commonVerifier:  commonVerifier,

		commonContributionCommitments: make(map[sharing.ID]hash_comm.Commitment),
		commonContributions:           make(map[sharing.ID][base.CollisionResistanceBytesCeil]byte),
		commonContributionWitnesses:   make(map[sharing.ID]hash_comm.Witness),

		commitmentKeys:                  make(map[sharing.ID]hash_comm.Key),
		pairwiseContributions:           make(map[sharing.ID][base.CollisionResistanceBytesCeil]byte),
		pairwiseContributionWitnesses:   make(map[sharing.ID]hash_comm.Witness),
		pairwiseContributionCommitments: make(map[sharing.ID]hash_comm.Commitment),
	}
	return p, nil
}

// SharingID returns the participant's sharing ID.
func (p *Participant) SharingID() sharing.ID {
	return p.id
}

// Round1 samples and broadcasts the participant's commitment key.
func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, ErrRound.WithMessage("invalid round")
	}

	var ck hash_comm.Key
	_, err := io.ReadFull(p.prng, ck[:])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample commitment key")
	}

	var commonContribution [base.CollisionResistanceBytesCeil]byte
	if _, err = io.ReadFull(p.prng, commonContribution[:]); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample common contribution")
	}
	commonContributionCommitment, commonContributionWitness, err := p.commonCommitter.Commit(commonContribution[:], p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to commit common contribution")
	}

	p.commitmentKeys[p.id] = ck
	p.commonContributions[p.id] = commonContribution
	p.commonContributionCommitments[p.id] = commonContributionCommitment
	p.commonContributionWitnesses[p.id] = commonContributionWitness

	outB := &Round1Broadcast{
		Ck:               ck,
		CommonCommitment: commonContributionCommitment,
	}
	p.round++
	return outB, nil
}

// Round2 collects commitment keys and sends commitment messages to peers.
func (p *Participant) Round2(inB network.RoundMessages[*Round1Broadcast, *Participant]) (*Round2Broadcast, network.OutgoingUnicasts[*Round2P2P, *Participant], error) {
	if p.round != 2 {
		return nil, nil, ErrRound.WithMessage("invalid round")
	}
	if err := network.ValidateIncomingMessages(p, p.otherParticipantsOrdered(), inB); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid incoming messages")
	}

	for id := range p.otherParticipantsOrdered() {
		b, ok := inB.Get(id)
		if !ok {
			return nil, nil, ErrInvalidArgument.WithMessage("missing broadcast from %d", id)
		}

		p.commitmentKeys[id] = b.Ck
		p.commonContributionCommitments[id] = b.CommonCommitment
	}

	bOut := &Round2Broadcast{
		CommonContribution:        p.commonContributions[p.id],
		CommonContributionWitness: p.commonContributionWitnesses[p.id],
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round2P2P]()
	for id := range p.otherParticipantsOrdered() {
		ck, ok := p.commitmentKeys[id]
		if !ok {
			return nil, nil, ErrInvalidArgument.WithMessage("missing commitment key for %d", id)
		}

		var pairwiseContribution [base.CollisionResistanceBytesCeil]byte
		if _, err := io.ReadFull(p.prng, pairwiseContribution[:]); err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to sample contribution")
		}
		p.pairwiseContributions[id] = pairwiseContribution
		scheme, err := hash_comm.NewScheme(ck)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to create commitment scheme")
		}
		committer, err := scheme.Committer()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to create committer")
		}
		pairwiseCommitment, pairwiseWitness, err := committer.Commit(pairwiseContribution[:], p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to commit contribution")
		}
		p.pairwiseContributionWitnesses[id] = pairwiseWitness
		uOut.Put(id, &Round2P2P{PairwiseContributionCommitment: pairwiseCommitment})
	}

	p.round++
	return bOut, uOut.Freeze(), nil
}

// Round3 receives peers' commitments and opens our contributions to them.
func (p *Participant) Round3(inB network.RoundMessages[*Round2Broadcast, *Participant], inU network.RoundMessages[*Round2P2P, *Participant]) (network.OutgoingUnicasts[*Round3P2P, *Participant], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("invalid round")
	}
	if errB := network.ValidateIncomingMessages(p, p.otherParticipantsOrdered(), inB); errB != nil {
		return nil, errs.Wrap(errB).WithMessage("invalid incoming messages")
	}
	if errU := network.ValidateIncomingMessages(p, p.otherParticipantsOrdered(), inU); errU != nil {
		return nil, errs.Wrap(errU).WithMessage("invalid incoming messages")
	}

	for id := range p.otherParticipantsOrdered() {
		b, ok := inB.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing broadcast from %d", id)
		}
		u, ok := inU.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing unicast from %d", id)
		}

		if err := p.commonVerifier.Verify(p.commonContributionCommitments[id], b.CommonContribution[:], b.CommonContributionWitness); err != nil {
			return nil, errs.Wrap(err).
				WithTag(base.IdentifiableAbortPartyIDTag, id).
				WithMessage("invalid common seed from %d", id)
		}
		p.commonContributions[id] = b.CommonContribution
		p.commonContributionWitnesses[id] = b.CommonContributionWitness
		p.pairwiseContributionCommitments[id] = u.PairwiseContributionCommitment
	}

	uOut := hashmap.NewComparable[sharing.ID, *Round3P2P]()
	for id := range p.otherParticipantsOrdered() {
		pairwiseContribution, ok := p.pairwiseContributions[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing contribution for %d", id)
		}
		pairwiseWitness, ok := p.pairwiseContributionWitnesses[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing contribution witness for %d", id)
		}
		uOut.Put(id, &Round3P2P{
			PairwiseContribution:        pairwiseContribution,
			PairwiseContributionWitness: pairwiseWitness,
		})
	}

	p.round++
	return uOut.Freeze(), nil
}

// Round4 verifies openings and derives the session context.
func (p *Participant) Round4(uIn network.RoundMessages[*Round3P2P, *Participant]) (*Context, error) {
	if p.round != 4 {
		return nil, ErrRound.WithMessage("invalid round")
	}
	if err := network.ValidateIncomingMessages(p, p.otherParticipantsOrdered(), uIn); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming messages")
	}

	ck, ok := p.commitmentKeys[p.id]
	if !ok {
		return nil, ErrInvalidArgument.WithMessage("missing local commitment key")
	}
	scheme, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment scheme")
	}
	verifier, err := scheme.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create verifier")
	}

	// collect all source of entropy
	const partyContributionEstimatedSize = 160
	commonSeed := make([]byte, 0, len(p.sortedQuorum)*partyContributionEstimatedSize)
	commonSeed = append(commonSeed, sessionDomainSeparator...)
	commonSeed = binary.LittleEndian.AppendUint64(commonSeed, uint64(len(p.sortedQuorum)))
	for _, id := range p.sortedQuorum {
		commonSeed = binary.LittleEndian.AppendUint64(commonSeed, uint64(id))
		ck, ok := p.commitmentKeys[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing commitment key for %d", id)
		}
		commonSeed = append(commonSeed, ck[:]...)
		c, ok := p.commonContributionCommitments[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing common commitment for %d", id)
		}
		commonSeed = append(commonSeed, c[:]...)
		m, ok := p.commonContributions[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing common contribution for %d", id)
		}
		commonSeed = append(commonSeed, m[:]...)
		w, ok := p.commonContributionWitnesses[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing common contribution witness for %d", id)
		}
		commonSeed = append(commonSeed, w[:]...)
	}

	pairwiseSeeds := make(map[sharing.ID][]byte)
	for id := range p.otherParticipantsOrdered() {
		u, ok := uIn.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing message from %d", id)
		}
		pairwiseCommitment, ok := p.pairwiseContributionCommitments[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing commitment from %d", id)
		}
		err := verifier.Verify(pairwiseCommitment, u.PairwiseContribution[:], u.PairwiseContributionWitness)
		if err != nil {
			return nil, errs.Wrap(err).
				WithTag(base.IdentifiableAbortPartyIDTag, id).
				WithMessage("invalid commitment from %d", id)
		}
		pairwiseSeed := new(bytes.Buffer)
		_, err = pairwiseSeed.WriteString(seedDomainSeparator)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to write seed domain separator")
		}
		_, err = pairwiseSeed.Write(commonSeed)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to write common seed")
		}
		myPairwiseContribution, ok := p.pairwiseContributions[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing contribution for %d", id)
		}
		theirPairwiseContribution := u.PairwiseContribution
		if p.id < id {
			_, err := pairwiseSeed.Write(myPairwiseContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
			_, err = pairwiseSeed.Write(theirPairwiseContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
		} else {
			_, err = pairwiseSeed.Write(theirPairwiseContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
			_, err := pairwiseSeed.Write(myPairwiseContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
		}
		pairwiseSeeds[id] = pairwiseSeed.Bytes()
	}

	ctx, err := NewContext(p.id, hashset.NewComparable(p.sortedQuorum...).Freeze(), commonSeed, pairwiseSeeds)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create session context")
	}
	p.round++
	return ctx, nil
}

func (p *Participant) otherParticipantsOrdered() iter.Seq[sharing.ID] {
	return func(yield func(sharing.ID) bool) {
		for _, id := range p.sortedQuorum {
			if id == p.id {
				continue
			}
			if ok := yield(id); !ok {
				return
			}
		}
	}
}
