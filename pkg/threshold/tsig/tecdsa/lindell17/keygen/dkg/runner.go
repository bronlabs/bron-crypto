package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "Lindell17DKGRound1"
	r2CorrelationID = "Lindell17DKGRound2"
	r3CorrelationID = "Lindell17DKGRound3"
	r4CorrelationID = "Lindell17DKGRound4"
	r5CorrelationID = "Lindell17DKGRound5"
	r6CorrelationID = "Lindell17DKGRound6"
	r7CorrelationID = "Lindell17DKGRound7"
)

type dkgRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant *Participant[P, B, S]
}

// NewRunner constructs a network runner that drives all Lindell17 DKG rounds.
func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	sid network.SID,
	shard *tecdsa.Shard[P, B, S],
	paillierKeyLen int,
	curve ecdsa.Curve[P, B, S],
	prng io.Reader,
	nic compiler.Name,
	tape transcripts.Transcript,
) (network.Runner[*lindell17.Shard[P, B, S]], error) {
	participant, err := NewParticipant(sid, shard, paillierKeyLen, curve, prng, nic, tape)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	return &dkgRunner[P, B, S]{participant: participant}, nil
}

func (r *dkgRunner[P, B, S]) Run(rt *network.Router) (*lindell17.Shard[P, B, S], error) {
	quorum := r.participant.shard.AccessStructure().Shareholders()

	r1Out, err := r.participant.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2In, err := exchange.BroadcastExchange(rt, r1CorrelationID, quorum, r1Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	r2Out, err := r.participant.Round2(r2In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3In, err := exchange.BroadcastExchange(rt, r2CorrelationID, quorum, r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	r3Out, err := r.participant.Round3(r3In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r4In, err := exchange.BroadcastExchange(rt, r3CorrelationID, quorum, r3Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}

	r4Out, err := r.participant.Round4(r4In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	r5In, err := exchange.UnicastExchange(rt, r4CorrelationID, r4Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 4 messages")
	}

	r5Out, err := r.participant.Round5(r5In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 5")
	}
	r6In, err := exchange.UnicastExchange(rt, r5CorrelationID, r5Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 5 messages")
	}

	r6Out, err := r.participant.Round6(r6In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 6")
	}
	r7In, err := exchange.UnicastExchange(rt, r6CorrelationID, r6Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 6 messages")
	}

	r7Out, err := r.participant.Round7(r7In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 7")
	}
	r8In, err := exchange.UnicastExchange(rt, r7CorrelationID, r7Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 7 messages")
	}

	shard, err := r.participant.Round8(r8In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 8")
	}
	return shard, nil
}
