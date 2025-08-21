package przsSetup

import (
	"crypto/subtle"
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Round1() (*Round1Broadcast, error) {
	seedContributions := hashmap.NewComparable[sharing.ID, [32]byte]()
	commitments := hashmap.NewComparable[sharing.ID, hash_comm.Commitment]()
	witnesses := hashmap.NewComparable[sharing.ID, hash_comm.Witness]()
	for sharingId := range p.quorum.Iter() {
		if sharingId == p.mySharingId {
			continue
		}

		var seedContribution [32]byte
		if _, err := io.ReadFull(p.prng, seedContribution[:]); err != nil {
			return nil, errs.WrapRandomSample(err, "cannot sample seed contribution")
		}

		seedContributionCommitment, seedContributionWitness, err := p.state.commitmentScheme.Committer().Commit(seedContribution[:], p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot commit seed contribution")
		}

		seedContributions.Put(sharingId, seedContribution)
		commitments.Put(sharingId, seedContributionCommitment)
		witnesses.Put(sharingId, seedContributionWitness)
	}

	p.state.seedContributions = seedContributions.Freeze()
	p.state.witnesses = witnesses.Freeze()
	p.state.commitments = hashmap.NewComparable[sharing.ID, ds.Map[sharing.ID, hash_comm.Commitment]]()
	p.state.commitments.Put(p.mySharingId, commitments.Freeze())
	r1bo := &Round1Broadcast{commitments: commitments.Freeze()}
	return r1bo, nil
}

func (p *Participant) Round2(r1bo network.RoundMessages[*Round1Broadcast]) (network.RoundMessages[*Round2P2P], error) {
	for sharingId := range p.quorum.Iter() {
		if sharingId == p.mySharingId {
			continue
		}

		msg, ok := r1bo.Get(sharingId)
		if !ok {
			return nil, errs.NewValidation("missing message from %d", sharingId)
		}
		p.state.commitments.Put(sharingId, msg.commitments)
	}

	r2uo := hashmap.NewComparable[sharing.ID, *Round2P2P]()
	for sharingId := range p.quorum.Iter() {
		if sharingId == p.mySharingId {
			continue
		}

		seedContribution, ok := p.state.seedContributions.Get(sharingId)
		if !ok {
			return nil, errs.NewValidation("missing seed contribution to %d", sharingId)
		}

		witness, ok := p.state.witnesses.Get(sharingId)
		if !ok {
			return nil, errs.NewValidation("missing seed witness to %d", sharingId)
		}

		r2uo.Put(sharingId, &Round2P2P{
			seedContribution: seedContribution,
			witness:          witness,
		})
	}

	return r2uo.Freeze(), nil
}

func (p *Participant) Round3(r2uo network.RoundMessages[*Round2P2P]) (przs.Seeds, error) {
	commonSeeds := hashmap.NewComparable[sharing.ID, [32]byte]()
	for sharingId := range p.quorum.Iter() {
		if sharingId == p.mySharingId {
			continue
		}

		msg, ok := r2uo.Get(sharingId)
		if !ok {
			return nil, errs.NewValidation("missing message from %d", sharingId)
		}
		theirSeedContribution := msg.seedContribution
		theirWitness := msg.witness
		theirCommitments, ok := p.state.commitments.Get(sharingId)
		if !ok {
			return nil, errs.NewValidation("missing commitments from %d", sharingId)
		}
		theirCommitment, ok := theirCommitments.Get(p.mySharingId)
		if !ok {
			return nil, errs.NewValidation("missing commitment for %d", sharingId)
		}
		if p.state.commitmentScheme.Verifier().Verify(theirCommitment, theirSeedContribution[:], theirWitness) != nil {
			return nil, errs.NewIdentifiableAbort(sharingId, "invalid seed contribution")
		}
		mySeedContribution, ok := p.state.seedContributions.Get(sharingId)
		var seed [32]byte
		subtle.XORBytes(seed[:], theirSeedContribution[:], mySeedContribution[:])
		commonSeeds.Put(sharingId, seed)
	}

	return commonSeeds.Freeze(), nil
}
