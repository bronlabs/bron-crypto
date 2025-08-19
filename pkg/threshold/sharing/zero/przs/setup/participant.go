package przsSetup

import (
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	domainSeparator = "BRON_CRYPTO_PRZS_SETUP_SID-"
)

type Participant struct {
	mySharingId sharing.ID
	quorum      network.Quorum
	tape        ts.Transcript
	prng        io.Reader
	state       State
}

type State struct {
	commitmentScheme *hash_comm.Scheme

	seedContributions ds.Map[sharing.ID, [32]byte]
	witnesses         ds.Map[sharing.ID, hash_comm.Witness]
	commitments       ds.MutableMap[sharing.ID, ds.Map[sharing.ID, hash_comm.Commitment]]
}

func NewParticipant(sessionId network.SID, mySharingId sharing.ID, quorum network.Quorum, tape ts.Transcript, prng io.Reader) (*Participant, error) {
	// TODO: add validation
	p := &Participant{
		mySharingId: mySharingId,
		quorum:      quorum,
		tape:        tape,
		prng:        prng,
	}
	p.tape.AppendBytes(domainSeparator, sessionId[:])

	var ck hash_comm.Key
	ckBytes, err := p.tape.ExtractBytes("ck", uint(len(ck)))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	p.state.commitmentScheme, err = hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create commitment scheme")
	}

	return p, nil
}

func (p *Participant) SharingID() sharing.ID {
	return p.mySharingId
}
