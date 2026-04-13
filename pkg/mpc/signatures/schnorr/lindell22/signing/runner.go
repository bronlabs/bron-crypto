package signing

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	mpcschnorr "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

const (
	r1CorrelationID = "Lindell22SigningRound1"
	r2CorrelationID = "Lindell22SigningRound2"
)

type signingRunner[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	cosigner *Cosigner[GE, S, M]
	message  M
}

// NewRunner constructs a network runner that drives the three Lindell22 signing rounds.
func NewRunner[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](
	ctx *session.Context,
	shard *lindell22.Shard[GE, S],
	niCompilerName compiler.Name,
	variant mpcschnorr.MPCFriendlyVariant[GE, S, M],
	message M,
	prng io.Reader,
) (network.Runner[*lindell22.PartialSignature[GE, S]], error) {
	cosigner, err := NewCosigner(ctx, shard, niCompilerName, variant, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create cosigner")
	}
	return &signingRunner[GE, S, M]{
		cosigner: cosigner,
		message:  message,
	}, nil
}

func (r *signingRunner[GE, S, M]) Run(rt *network.Router) (*lindell22.PartialSignature[GE, S], error) {
	r1bOut, r1uOut, err := r.cosigner.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	r2bIn, r2uIn, err := exchange.Exchange(rt, r1CorrelationID, r.cosigner.Quorum(), r1bOut, r1uOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	r2bOut, err := r.cosigner.Round2(r2bIn, r2uIn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	r3bIn, err := exchange.BroadcastExchange(rt, r2CorrelationID, r.cosigner.Quorum(), r2bOut)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	psig, err := r.cosigner.Round3(r3bIn, r.message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	return psig, nil
}
