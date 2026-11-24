package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
)

// SignResult is the output of a signing runner: this party's partial
// signature and an aggregator bound to the session, which performs the
// nonce-consistency and sign-consistency checks against the session's state.
// Callers exchange the partial signatures at the application layer and
// aggregate them into the final ECDSA signature.
type SignResult[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	aggregator       PartialSignatureAggregator[P, B, S]
	partialSignature *dkls23.PartialSignature[P, B, S]
}

// NewSignResult pairs a partial signature with its cosigning aggregator.
func NewSignResult[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](aggregator PartialSignatureAggregator[P, B, S], partialSignature *dkls23.PartialSignature[P, B, S]) (*SignResult[P, B, S], error) {
	if aggregator == nil || partialSignature == nil {
		return nil, ErrInvalidArgument.WithMessage("aggregator and partial signature must not be nil")
	}
	return &SignResult[P, B, S]{aggregator: aggregator, partialSignature: partialSignature}, nil
}

// PartialSignatureCosigningAggregator returns the session-bound aggregator.
func (r *SignResult[P, B, S]) PartialSignatureCosigningAggregator() PartialSignatureAggregator[P, B, S] {
	return r.aggregator
}

// PartialSignature returns this party's partial signature.
func (r *SignResult[P, B, S]) PartialSignature() *dkls23.PartialSignature[P, B, S] {
	return r.partialSignature
}
