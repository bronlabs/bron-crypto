package aor

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// NewAgreeOnRandomRunner constructs a runner that executes the Agree-on-Random protocol.
func NewAgreeOnRandomRunner(id sharing.ID, quorum network.Quorum, sampleSize int, tape transcripts.Transcript, prng io.Reader) (network.Runner[[]byte], error) {
	party, err := NewParticipant(id, quorum, sampleSize, tape, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}

	return &agreeOnRandomRunner{participant: party}, nil
}

type agreeOnRandomRunner struct {
	participant *Participant
}

// Run executes the three-round Agree-on-Random protocol over the provided message router.
func (r *agreeOnRandomRunner) Run(rt *network.Router) ([]byte, error) {
	// r1
	r1Out, err := r.participant.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2In, err := exchange.Broadcast(rt, "AgreeOnRandomRound1Broadcast", r1Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r2
	r2Out, err := r.participant.Round2(r2In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3In, err := exchange.Broadcast(rt, "AgreeOnRandomRound2Broadcast", r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange broadcast")
	}

	// r3
	sample, err := r.participant.Round3(r3In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}

	return sample, nil
}
