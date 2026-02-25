package sign

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

const (
	r1CorrelationID = "DKLS23SignRound1"
	r2CorrelationID = "DKLS23SignRound2"
	r3CorrelationID = "DKLS23SignRound3"
	r4CorrelationID = "DKLS23SignRound4"
)

type signRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	cosigner *Cosigner[P, B, S]
	message  []byte
}

func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	sessionID network.SID,
	quorum network.Quorum,
	suite *ecdsa.Suite[P, B, S],
	shard *dkls23.Shard[P, B, S],
	message []byte,
	prng io.Reader,
	tape transcripts.Transcript,
) (network.Runner[*dkls23.PartialSignature[P, B, S]], error) {
	cosigner, err := NewCosigner(sessionID, quorum, suite, shard, prng, tape)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create cosigner")
	}
	return &signRunner[P, B, S]{cosigner: cosigner, message: message}, nil
}

func (r *signRunner[P, B, S]) Run(rt *network.Router) (*dkls23.PartialSignature[P, B, S], error) {
	r1uOut, err := r.cosigner.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2uIn, err := exchange.UnicastExchange(rt, r1CorrelationID, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	r2uOut, err := r.cosigner.Round2(r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3uIn, err := exchange.UnicastExchange(rt, r2CorrelationID, r2uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	r3bOut, r3uOut, err := r.cosigner.Round3(r3uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	r4bIn, r4uIn, err := exchange.Exchange(rt, r3CorrelationID, r.cosigner.quorum, r3bOut, r3uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}

	r4bOut, r4uOut, err := r.cosigner.Round4(r4bIn, r4uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	r5bIn, r5uIn, err := exchange.Exchange(rt, r4CorrelationID, r.cosigner.quorum, r4bOut, r4uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 4 messages")
	}

	psig, err := r.cosigner.Round5(r5bIn, r5uIn, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 5")
	}
	return psig, nil
}
