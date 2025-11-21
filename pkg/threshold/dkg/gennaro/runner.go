package gennaro

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type gennaroDkgRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	party *Participant[G, S]
}

func NewGennaroDKGRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], sessionId network.SID, sharingId sharing.ID, accessStructure *shamir.AccessStructure, tape ts.Transcript, prng io.Reader) (network.Runner[*DKGOutput[G, S]], error) {
	party, err := NewParticipant(sessionId, group, sharingId, accessStructure, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create participant")
	}
	return &gennaroDkgRunner[G, S]{party}, nil
}

func (r *gennaroDkgRunner[G, S]) Run(rt *network.Router) (*DKGOutput[G, S], error) {
	// r1
	r1OutB, err := r.party.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1")
	}
	r2InB, err := exchange.ExchangeBroadcast(rt, "GennaroDKGRound1", r1OutB)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}

	// r2
	r2OutB, r2OutU, err := r.party.Round2(r2InB)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2")
	}
	r3InB, r3InU, err := exchange.Exchange(rt, "GennaroDKGRound2", r2OutB, r2OutU)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange broadcast")
	}

	// r3
	dkgOutput, err := r.party.Round3(r3InB, r3InU)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3")
	}

	return dkgOutput, nil
}
