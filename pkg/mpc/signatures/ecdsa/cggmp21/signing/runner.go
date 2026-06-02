package signing

import (
	"context"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// ProtocolName identifies the CGGMP21 signing runner in notifications.
	ProtocolName = "CGGMP21_Signing"

	r1CorrelationID = "CGGMP21SignRound1"
	r2CorrelationID = "CGGMP21SignRound2"
	r3CorrelationID = "CGGMP21SignRound3"
	r4CorrelationID = "CGGMP21SignRound4"
)

type signRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	signer  *Signer[P, B, S]
	message []byte
}

func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	suite *sigecdsa.Suite[P, B, S],
	shard *cggmp21.Shard[P, B, S],
	message []byte,
	prng io.Reader,
) (network.Runner[*sigecdsa.Signature[S]], error) {
	signer, err := NewSigner(ctx, suite, shard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create signer")
	}
	return &signRunner[P, B, S]{
		signer:  signer,
		message: message,
	}, nil
}

func (r *signRunner[P, B, S]) Run(ctx context.Context, rt *network.Router, notificationCallback network.NotificationCallback) (*sigecdsa.Signature[S], error) {
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
	psig, err := r.signer.Round4(r4bIn, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	network.NotifyRoundCompleted(notificationCallback, ProtocolName, 4)

	psigOut := hashmap.NewComparable[sharing.ID, *Round4P2P[P, B, S]]()
	for id := range r.signer.ctx.OtherPartiesOrdered() {
		psigOut.Put(id, &Round4P2P[P, B, S]{
			PartialSignature: psig,
		})
	}
	psigIn, err := exchange.UnicastExchange(ctx, rt, r4CorrelationID, psigOut.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange partial signatures")
	}
	if err := network.ValidateIncomingMessages(r.signer, r.signer.ctx.OtherPartiesOrdered(), psigIn); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid partial signatures")
	}
	partialSignatures := map[sharing.ID]*cggmp21.PartialSignature[P, B, S]{
		r.signer.ctx.HolderID(): psig,
	}
	for id, msg := range psigIn.Iter() {
		partialSignatures[id] = msg.PartialSignature
	}

	signature, err := r.signer.Aggregate(partialSignatures)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot aggregate signature")
	}
	return signature, nil
}
