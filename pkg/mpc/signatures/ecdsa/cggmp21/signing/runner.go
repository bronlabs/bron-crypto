package signing

import (
	"context"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// ProtocolName identifies the CGGMP21 signing runner in notifications.
	ProtocolName = "CGGMP21_Signing"

	r1CorrelationID       = "CGGMP21SignRound1"
	r2CorrelationID       = "CGGMP21SignRound2"
	r3CorrelationID       = "CGGMP21SignRound3"
	redAlertCorrelationID = "CGGMP21SignRedAlert"
)

type signRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	signer  *Signer[P, B, S]
	message []byte
}

// SignResult is the output of the online signing runner.
type SignResult[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	aggregator       PartialSignatureAggregator[P, B, S]
	partialSignature *cggmp21.PartialSignature[P, B, S]
}

// PartialSignatureOnlineAggregator returns the signer-backed aggregator for this signing session.
func (r *SignResult[P, B, S]) PartialSignatureOnlineAggregator() PartialSignatureAggregator[P, B, S] {
	return r.aggregator
}

// PartialSignature returns this party's partial signature.
func (r *SignResult[P, B, S]) PartialSignature() *cggmp21.PartialSignature[P, B, S] {
	return r.partialSignature
}

// NewRunner constructs a CGGMP21 signing runner.
func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	suite *sigecdsa.Suite[P, B, S],
	shard *cggmp21.Shard[P, B, S],
	message []byte,
	prng io.Reader,
) (network.Runner[*SignResult[P, B, S]], error) {
	signer, err := NewSigner(ctx, suite, shard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create signer")
	}
	return &signRunner[P, B, S]{
		signer:  signer,
		message: message,
	}, nil
}

func (r *signRunner[P, B, S]) Run(ctx context.Context, rt *network.Router, notificationCallback network.NotificationCallback) (*SignResult[P, B, S], error) {
	// r1
	r1bOut, r1uOut, err := r.signer.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 1)

	// r2
	r2bIn, r2uIn, err := exchange.Exchange(ctx, rt, r1CorrelationID, r.signer.ctx.Quorum(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}
	r2bOut, r2uOut, err := r.signer.Round2(r2bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 2)

	// r3
	r3bIn, r3uIn, err := exchange.Exchange(ctx, rt, r2CorrelationID, r.signer.ctx.Quorum(), r2bOut, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}
	r3bOut, err := r.signer.Round3(r3bIn, r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 3)

	// r4
	r4bIn, err := exchange.BroadcastExchange(ctx, rt, r3CorrelationID, r.signer.ctx.Quorum(), r3bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}
	psig, redAlertParticipant, err := r.signer.Round4(r4bIn, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	if redAlertParticipant != nil {
		redAlertOut, err := redAlertParticipant.Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run red alert round 1")
		}
		redAlertIn, err := exchange.BroadcastExchange(ctx, rt, redAlertCorrelationID, r.signer.ctx.Quorum(), redAlertOut)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot exchange red alert broadcasts")
		}
		if err := redAlertParticipant.Round2(redAlertIn); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot verify red alert broadcasts")
		}
		return nil, base.ErrAbort.WithMessage("red alert completed without identifying a culprit")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 4)

	return &SignResult[P, B, S]{
		aggregator:       &onlineAggregator[P, B, S]{signer: r.signer},
		partialSignature: psig,
	}, nil
}
