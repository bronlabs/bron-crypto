package session

import (
	"bytes"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/errs-go/errs"
)

// Participant runs the session seed setup protocol.
type Participant struct {
	id           sharing.ID
	sortedQuorum []sharing.ID
	prng         io.Reader

	round                 int
	commitmentKeys        map[sharing.ID]hash_comm.Key
	commonSeed            []byte
	contributions         map[sharing.ID][32]byte
	contributionWitnesses map[sharing.ID]hash_comm.Witness
	commitments           map[sharing.ID]hash_comm.Commitment
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

	//nolint:exhaustruct // lazy initialise state
	p := &Participant{
		id:                    id,
		sortedQuorum:          sortedQuorum,
		prng:                  prng,
		round:                 1,
		commitmentKeys:        make(map[sharing.ID]hash_comm.Key),
		contributions:         make(map[sharing.ID][32]byte),
		contributionWitnesses: make(map[sharing.ID]hash_comm.Witness),
		commitments:           make(map[sharing.ID]hash_comm.Commitment),
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
	p.commitmentKeys[p.id] = ck

	outB := &Round1Broadcast{Ck: ck}
	p.round++
	return outB, nil
}

// Round2 collects commitment keys and sends commitment messages to peers.
func (p *Participant) Round2(inB network.RoundMessages[*Round1Broadcast]) (network.OutgoingUnicasts[*Round2P2P], error) {
	if p.round != 2 {
		return nil, ErrRound.WithMessage("invalid round")
	}

	for _, id := range p.sortedQuorum {
		if id == p.id {
			continue
		}

		b, ok := inB.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing broadcast from %d", id)
		}
		p.commitmentKeys[id] = b.Ck
	}

	commonData := new(bytes.Buffer)
	for _, id := range p.sortedQuorum {
		ck, ok := p.commitmentKeys[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing commitment key for %d", id)
		}
		_, err := commonData.Write(ck[:])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to write commitment key")
		}
	}
	p.commonSeed = commonData.Bytes()

	uOut := hashmap.NewComparable[sharing.ID, *Round2P2P]()
	for _, id := range p.sortedQuorum {
		if id == p.id {
			continue
		}

		ck, ok := p.commitmentKeys[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing commitment key for %d", id)
		}
		var contribution [32]byte
		_, err := io.ReadFull(p.prng, contribution[:])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to sample contribution")
		}
		p.contributions[id] = contribution
		scheme, err := hash_comm.NewScheme(ck)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create commitment scheme")
		}
		committer, err := scheme.Committer()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create committer")
		}
		commitment, witness, err := committer.Commit(contribution[:], p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to commit contribution")
		}
		p.contributionWitnesses[id] = witness
		uOut.Put(id, &Round2P2P{Commitment: commitment})
	}

	p.round++
	return uOut.Freeze(), nil
}

// Round3 receives peers' commitments and opens our contributions to them.
func (p *Participant) Round3(inU network.RoundMessages[*Round2P2P]) (network.OutgoingUnicasts[*Round3P2P], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("invalid round")
	}

	for _, id := range p.sortedQuorum {
		if id == p.id {
			continue
		}

		u, ok := inU.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing unicast from %d", id)
		}
		p.commitments[id] = u.Commitment
	}

	uOut := hashmap.NewComparable[sharing.ID, *Round3P2P]()
	for _, id := range p.sortedQuorum {
		if id == p.id {
			continue
		}
		contribution, ok := p.contributions[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing contribution for %d", id)
		}
		witness, ok := p.contributionWitnesses[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing contribution witness for %d", id)
		}
		uOut.Put(id, &Round3P2P{
			Contribution:        contribution,
			ContributionWitness: witness,
		})
	}

	p.round++
	return uOut.Freeze(), nil
}

// Round4 verifies openings and derives the session context.
func (p *Participant) Round4(uIn network.RoundMessages[*Round3P2P]) (*Context, error) {
	if p.round != 4 {
		return nil, ErrRound.WithMessage("invalid round")
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

	seeds := make(map[sharing.ID][]byte)
	for _, id := range p.sortedQuorum {
		if id == p.id {
			continue
		}

		u, ok := uIn.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing message from %d", id)
		}
		commitment, ok := p.commitments[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing commitment from %d", id)
		}
		err := verifier.Verify(commitment, u.Contribution[:], u.ContributionWitness)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("invalid commitment from %d", id)
		}
		seed := new(bytes.Buffer)
		myContribution, ok := p.contributions[id]
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing contribution for %d", id)
		}
		theirContribution := u.Contribution

		if p.id < id {
			_, err := seed.Write(myContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
			_, err = seed.Write(theirContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
		} else {
			_, err = seed.Write(theirContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
			_, err := seed.Write(myContribution[:])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to write contribution")
			}
		}
		seeds[id] = seed.Bytes()
	}

	ctx, err := NewContext(p.id, hashset.NewComparable(p.sortedQuorum...).Freeze(), p.commonSeed, seeds)
	if err != nil {
		return nil, err
	}
	p.round++
	return ctx, nil
}
