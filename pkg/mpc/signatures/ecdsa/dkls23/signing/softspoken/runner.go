package signing_softspoken

import (
	"context"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// ProtocolName identifies this signing runner in notifications.
	ProtocolName = "DKLS23_Signing_SoftSpoken"

	r1CorrelationID = "DKLS23SignSoftSpokenRound1"
	r2CorrelationID = "DKLS23SignSoftSpokenRound2"
	r3CorrelationID = "DKLS23SignSoftSpokenRound3"
)

type signRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	cosigner *Cosigner[P, B, S]
	message  []byte
}

// NewRunner builds a runner that signs message with the cosigner of ctx.
func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	suite *ecdsa.Suite[P, B, S],
	shard *dkls23.Shard[P, B, S],
	message []byte,
	prng io.Reader,
) (network.Runner[*signing.SignResult[P, B, S]], error) {
	cosigner, err := NewCosigner(ctx, suite, shard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the cosigner")
	}
	return &signRunner[P, B, S]{cosigner: cosigner, message: message}, nil
}

// Run executes the four rounds over the router and returns the partial
// signature with its cosigning aggregator.
func (r *signRunner[P, B, S]) Run(ctx context.Context, rt *network.Router, notificationCallback network.NotificationCallback) (*signing.SignResult[P, B, S], error) {
	r1bOut, r1uOut, err := r.cosigner.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 1)

	r2bIn, r2uIn, err := exchange.Exchange(ctx, rt, r1CorrelationID, r.cosigner.Quorum(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}
	r2uOut, err := r.cosigner.Round2(r2bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 2)

	r3uIn, err := exchange.UnicastExchange(ctx, rt, r2CorrelationID, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}
	r3bOut, r3uOut, err := r.cosigner.Round3(r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 3)

	r4bIn, r4uIn, err := exchange.Exchange(ctx, rt, r3CorrelationID, r.cosigner.Quorum(), r3bOut, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}
	partialSignature, err := r.cosigner.Round4(r4bIn, r4uIn, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 4)

	aggregator, err := signing.NewCosigningAggregator(r.cosigner.Core())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the aggregator")
	}
	result, err := signing.NewSignResult(aggregator, partialSignature)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot build the result")
	}
	return result, nil
}
