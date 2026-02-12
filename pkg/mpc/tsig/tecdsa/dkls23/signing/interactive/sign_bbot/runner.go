package sign_bbot

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "DKLS23SignBBOTRound1"
	r2CorrelationID = "DKLS23SignBBOTRound2"
	r3CorrelationID = "DKLS23SignBBOTRound3"
)

type signRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	cosigner *Cosigner[P, B, S]
	message  []byte
}

func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	suite *ecdsa.Suite[P, B, S],
	shard *dkls23.Shard[P, B, S],
	message []byte,
	prng io.Reader,
) (network.Runner[*dkls23.PartialSignature[P, B, S]], error) {
	cosigner, err := NewCosigner(ctx, suite, shard, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create cosigner")
	}
	return &signRunner[P, B, S]{cosigner: cosigner, message: message}, nil
}

func (r *signRunner[P, B, S]) Run(rt *network.Router) (*dkls23.PartialSignature[P, B, S], error) {
	r1bOut, r1uOut, err := r.cosigner.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2bIn, r2uIn, err := exchange.Exchange(rt, r1CorrelationID, r.cosigner.ctx.Quorum(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	r2bOut, r2uOut, err := r.cosigner.Round2(r2bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3bIn, r3uIn, err := exchange.Exchange(rt, r2CorrelationID, r.cosigner.ctx.Quorum(), r2bOut, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	r3bOut, r3uOut, err := r.cosigner.Round3(r3bIn, r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r4bIn, r4uIn, err := exchange.Exchange(rt, r3CorrelationID, r.cosigner.ctx.Quorum(), r3bOut, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}

	psig, err := r.cosigner.Round4(r4bIn, r4uIn, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	return psig, nil
}
