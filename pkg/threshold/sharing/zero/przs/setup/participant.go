package przssetup

import (
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	domainSeparator = "BRON_CRYPTO_PRZS_SETUP_SID-"
)

// Participant runs the PRZS seed-setup protocol.
type Participant struct {
	mySharingID sharing.ID
	quorum      network.Quorum
	tape        ts.Transcript
	prng        io.Reader
	state       State
}

// State stores commitments and seed material across rounds.
type State struct {
	commitmentScheme *hash_comm.Scheme

	seedContributions ds.Map[sharing.ID, [przs.SeedLength]byte]
	witnesses         ds.Map[sharing.ID, hash_comm.Witness]
	commitments       ds.MutableMap[sharing.ID, ds.Map[sharing.ID, hash_comm.Commitment]]
}

// NewParticipant initialises the seed setup for a given session.
func NewParticipant(sessionID network.SID, mySharingID sharing.ID, quorum network.Quorum, tape ts.Transcript, prng io.Reader) (*Participant, error) {
	// TODO: add validation
	p := &Participant{
		mySharingID: mySharingID,
		quorum:      quorum,
		tape:        tape,
		prng:        prng,
		state: State{
			commitmentScheme:  nil,
			seedContributions: nil,
			witnesses:         nil,
			commitments:       nil,
		},
	}
	p.tape.AppendBytes(domainSeparator, sessionID[:])

	var ck hash_comm.Key
	ckBytes, err := p.tape.ExtractBytes("ck", uint(len(ck)))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	p.state.commitmentScheme, err = hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create commitment scheme")
	}

	return p, nil
}

// SharingID returns the participant identifier.
func (p *Participant) SharingID() sharing.ID {
	return p.mySharingID
}
