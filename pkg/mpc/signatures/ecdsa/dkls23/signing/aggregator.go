package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// PartialSignatureAggregator combines DKLs23 partial signatures into an ECDSA
// signature. Both implementations perform the two output checks of the refined
// protocol of Segev (eprint 2026/929, Step 4): the nonce-consistency check,
// that every partial signature carries the same aggregated nonce point R, and
// the sign-consistency check, that the signature reconstructs that R and not
// its negation. Without them a computationally unbounded adversary can make
// two honest parties output different valid signatures, which no ideal
// signing functionality can simulate.
type PartialSignatureAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] interface {
	// Aggregate combines the partial signatures keyed by cosigner identifier.
	Aggregate(map[sharing.ID]*dkls23.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error)
}

type cosigningAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	core *Core[P, B, S]
}

// NewCosigningAggregator returns the aggregator of a cosigner whose core has
// produced its partial signature. It compares every partial signature against
// the nonce point the cosigner itself aggregated, so a mismatch is attributed
// to its sender, and it requires a partial signature from every party of the
// quorum. It can be used once: aggregation consumes the session state.
func NewCosigningAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](core *Core[P, B, S]) (PartialSignatureAggregator[P, B, S], error) {
	if core == nil {
		return nil, ErrInvalidArgument.WithMessage("core must not be nil")
	}
	if !core.signed {
		return nil, ErrRound.WithMessage("the cosigner has not produced its partial signature")
	}
	if core.aggregated {
		return nil, ErrRound.WithMessage("the cosigner has already aggregated the signature")
	}
	return &cosigningAggregator[P, B, S]{core: core}, nil
}

// Aggregate combines the partial signatures using the signing session's state.
func (a *cosigningAggregator[P, B, S]) Aggregate(partialSignatures map[sharing.ID]*dkls23.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	return a.core.aggregate(partialSignatures)
}

// aggregate is the output step of Segev's refined protocol run by a cosigner.
func (c *Core[P, B, S]) aggregate(partialSignatures map[sharing.ID]*dkls23.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if !c.signed || c.aggregated {
		return nil, ErrRound.WithMessage("no partial signature to aggregate with, or already aggregated")
	}
	field := c.suite.ScalarField()
	u, w := field.Zero(), field.Zero()
	for id := range c.ctx.AllPartiesOrdered() {
		psig, ok := partialSignatures[id]
		if !ok || psig == nil {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("missing partial signature from %d", id)
		}
		// Nonce-consistency check (Segev, Step 4a): the sender must have
		// aggregated the same R as this party.
		if !psig.R().Equal(c.nonce) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("nonce mismatch in partial signature from %d", id)
		}
		u = u.Add(psig.U())
		w = w.Add(psig.W())
	}

	uInv, err := u.TryInv()
	if err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("cannot compute w/u")
	}
	s := w.Mul(uInv)

	// Sign-consistency check (Segev, Step 4c): the signature must reconstruct
	// the agreed R itself. A share that yields −s instead passes ECDSA
	// verification but reconstructs −R, and would split the honest outputs.
	sInv, err := s.TryInv()
	if err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("signature scalar is zero")
	}
	reconstructed := c.suite.Curve().ScalarBaseMul(sInv.Mul(c.m)).Add(c.shard.PublicKey().Value().ScalarMul(sInv.Mul(c.rx)))
	if !reconstructed.Equal(c.nonce) {
		return nil, base.ErrAbort.WithMessage("sign-consistency check failed: the signature does not reconstruct the agreed nonce")
	}

	signature, err := buildSignature(c.nonce, c.rx, s)
	if err != nil {
		return nil, err
	}
	verifier, err := sigecdsa.NewVerifier(c.suite)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the verifier")
	}
	if err := verifier.Verify(signature, c.shard.PublicKey(), c.message); err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("signature is invalid")
	}

	c.aggregated = true
	return signature, nil
}

type nonCosigningAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite     *sigecdsa.Suite[P, B, S]
	publicKey *sigecdsa.PublicKey[P, B, S]
	message   []byte
}

// NewNonCosigningAggregator returns a stateless aggregator for a party that did
// not take part in the signing session. It requires all partial signatures to
// carry the same nonce and reports disagreement as an unattributed abort.
// It enforces sign consistency through the low-s rule, the alternative Segev
// allows for Step 4c.
func NewNonCosigningAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *sigecdsa.Suite[P, B, S], publicKey *sigecdsa.PublicKey[P, B, S], message []byte) (PartialSignatureAggregator[P, B, S], error) {
	if suite == nil || publicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("suite and public key must not be nil")
	}
	return &nonCosigningAggregator[P, B, S]{suite: suite, publicKey: publicKey, message: message}, nil
}

// Aggregate combines the partial signatures without signing session state.
func (a *nonCosigningAggregator[P, B, S]) Aggregate(partialSignatures map[sharing.ID]*dkls23.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if len(partialSignatures) == 0 {
		return nil, ErrInvalidArgument.WithMessage("no partial signatures")
	}
	field := a.suite.ScalarField()
	u, w := field.Zero(), field.Zero()
	var nonce P
	first := true
	for id, psig := range partialSignatures {
		if psig == nil {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("missing partial signature from %d", id)
		}
		if first {
			nonce = psig.R()
			first = false
		} else if !psig.R().Equal(nonce) {
			return nil, base.ErrAbort.WithMessage("partial signatures disagree on the nonce")
		}
		u = u.Add(psig.U())
		w = w.Add(psig.W())
	}

	uInv, err := u.TryInv()
	if err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("cannot compute w/u")
	}
	rxCoordinate, err := nonce.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot take the x-coordinate of R")
	}
	rx, err := field.FromWideBytes(rxCoordinate.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert the x-coordinate to a scalar")
	}
	signature, err := buildSignature(nonce, rx, w.Mul(uInv))
	if err != nil {
		return nil, err
	}
	verifier, err := sigecdsa.NewVerifier(a.suite)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create the verifier")
	}
	if err := verifier.Verify(signature, a.publicKey, a.message); err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("signature is invalid")
	}
	return signature, nil
}

// buildSignature assembles (r_x, s) with its recovery identifier and
// normalises it to low-s, which fixes the sign of s canonically so that every
// honest aggregator outputs the same signature.
func buildSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](nonce P, rx, s S) (*sigecdsa.Signature[S], error) {
	v, err := sigecdsa.ComputeRecoveryID(nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute the recovery identifier")
	}
	signature, err := sigecdsa.NewSignature(rx, s, &v)
	if err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("cannot create the signature")
	}
	signature.Normalise()
	return signature, nil
}
