package presign_softspoken

import (
	"context"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing_softspoken"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// ProtocolName identifies the DKLS23 soft-spoken presignature runner in notifications.
	ProtocolName = "DKLS23_Presign_SoftSpoken"

	r1CorrelationID = "DKLS23PresignRound1"
	r2CorrelationID = "DKLS23PresignRound2"
	r3CorrelationID = "DKLS23PresignRound3"
	r4CorrelationID = "DKLS23PresignRound4"
)

type pregenRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	cosigner *signing_softspoken.Cosigner[P, B, S]
}

func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	suite *ecdsa.Suite[P, B, S],
	shard *dkls23.Shard[P, B, S],
	prng io.Reader,
) (network.Runner[*dkls23.PreSignature[P, B, S]], error) {
	cosigner, err := signing_softspoken.NewCosigner(ctx, suite, shard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create cosigner")
	}
	return &pregenRunner[P, B, S]{cosigner: cosigner}, nil
}

func (r *pregenRunner[P, B, S]) Run(ctx context.Context, rt *network.Router, notificationCallback network.NotificationCallback) (*dkls23.PreSignature[P, B, S], error) {
	// r1
	r1uOut, err := r.cosigner.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 1)

	// r2
	r2uIn, err := exchange.UnicastExchange(ctx, rt, r1CorrelationID, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}
	r2uOut, err := r.cosigner.Round2(r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 2)

	// r3
	r3uIn, err := exchange.UnicastExchange(ctx, rt, r2CorrelationID, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}
	r3bOut, r3uOut, err := r.cosigner.Round3(r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 3)

	// r4
	r4bIn, r4uIn, err := exchange.Exchange(ctx, rt, r3CorrelationID, r.cosigner.Quorum(), r3bOut, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}
	r4bOut, r4uOut, err := r.cosigner.Round4(r4bIn, r4uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 4)

	// presign: message-independent part of r5
	r5bIn, r5uIn, err := exchange.Exchange(ctx, rt, r4CorrelationID, r.cosigner.Quorum(), r4bOut, r4uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 4 messages")
	}
	preSignature, err := r.cosigner.PreSign(r5bIn, r5uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run presign")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 5)

	return preSignature, nil
}
