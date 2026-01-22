package przssetup

import (
	"crypto/subtle"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/errs-go/pkg/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

// Round1 samples pairwise seed contributions and commits to them.
func (p *Participant) Round1() (*Round1Broadcast, error) {
	seedContributions := hashmap.NewComparable[sharing.ID, [przs.SeedLength]byte]()
	commitments := hashmap.NewComparable[sharing.ID, hash_comm.Commitment]()
	witnesses := hashmap.NewComparable[sharing.ID, hash_comm.Witness]()
	for sharingID := range p.quorum.Iter() {
		if sharingID == p.mySharingID {
			continue
		}

		var seedContribution [przs.SeedLength]byte
		if _, err := io.ReadFull(p.prng, seedContribution[:]); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample seed contribution")
		}

		committer, err := p.state.commitmentScheme.Committer()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create committer")
		}
		seedContributionCommitment, seedContributionWitness, err := committer.Commit(seedContribution[:], p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot commit seed contribution")
		}

		seedContributions.Put(sharingID, seedContribution)
		commitments.Put(sharingID, seedContributionCommitment)
		witnesses.Put(sharingID, seedContributionWitness)
	}

	p.state.seedContributions = seedContributions.Freeze()
	p.state.witnesses = witnesses.Freeze()
	p.state.commitments = hashmap.NewComparable[sharing.ID, ds.Map[sharing.ID, hash_comm.Commitment]]()
	p.state.commitments.Put(p.mySharingID, commitments.Freeze())
	r1bo := &Round1Broadcast{Commitments: commitments.ToNative()}
	return r1bo, nil
}

// Round2 opens committed seed contributions to each counterparty.
func (p *Participant) Round2(r1bo network.RoundMessages[*Round1Broadcast]) (network.RoundMessages[*Round2P2P], error) {
	for sharingID := range p.quorum.Iter() {
		if sharingID == p.mySharingID {
			continue
		}

		msg, ok := r1bo.Get(sharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message from %d", sharingID)
		}
		p.state.commitments.Put(sharingID, hashmap.NewImmutableComparableFromNativeLike(msg.Commitments))
	}

	r2uo := hashmap.NewComparable[sharing.ID, *Round2P2P]()
	for sharingID := range p.quorum.Iter() {
		if sharingID == p.mySharingID {
			continue
		}

		seedContribution, ok := p.state.seedContributions.Get(sharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing seed contribution to %d", sharingID)
		}

		witness, ok := p.state.witnesses.Get(sharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing seed witness to %d", sharingID)
		}

		r2uo.Put(sharingID, &Round2P2P{
			SeedContribution: seedContribution,
			Witness:          witness,
		})
	}

	return r2uo.Freeze(), nil
}

// Round3 verifies peers' openings and derives pairwise seeds.
func (p *Participant) Round3(r2uo network.RoundMessages[*Round2P2P]) (przs.Seeds, error) {
	commonSeeds := hashmap.NewComparable[sharing.ID, [przs.SeedLength]byte]()
	for sharingID := range p.quorum.Iter() {
		if sharingID == p.mySharingID {
			continue
		}

		msg, ok := r2uo.Get(sharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing message from %d", sharingID)
		}
		theirSeedContribution := msg.SeedContribution
		theirWitness := msg.Witness
		theirCommitments, ok := p.state.commitments.Get(sharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing commitments from %d", sharingID)
		}
		theirCommitment, ok := theirCommitments.Get(p.mySharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing commitment for %d", sharingID)
		}
		verifier, err := p.state.commitmentScheme.Verifier()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create verifier")
		}
		if verifier.Verify(theirCommitment, theirSeedContribution[:], theirWitness) != nil {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, sharingID).WithMessage("invalid seed contribution")
		}
		mySeedContribution, ok := p.state.seedContributions.Get(sharingID)
		if !ok {
			return nil, ErrFailed.WithMessage("missing seed for %d", sharingID)
		}
		var seed [przs.SeedLength]byte
		subtle.XORBytes(seed[:], theirSeedContribution[:], mySeedContribution[:])
		commonSeeds.Put(sharingID, seed)
	}

	return commonSeeds.Freeze(), nil
}
