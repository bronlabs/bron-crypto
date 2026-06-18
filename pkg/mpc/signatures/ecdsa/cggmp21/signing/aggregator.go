package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// PartialSignatureAggregator combines CGGMP21 partial signatures into an ECDSA signature.
type PartialSignatureAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] interface {
	// Aggregate combines partial signatures keyed by signer ID.
	Aggregate(map[sharing.ID]*cggmp21.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error)
}

type onlineAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	signer *Signer[P, B, S]
}

// Aggregate combines partial signatures using the online signing session state.
func (a *onlineAggregator[P, B, S]) Aggregate(ps map[sharing.ID]*cggmp21.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	return a.signer.aggregate(ps)
}

type offlineAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve sigecdsa.Curve[P, B, S]
}

// NewOfflineAggregator constructs a stateless aggregator for CGGMP21 partial signatures.
func NewOfflineAggregator[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve sigecdsa.Curve[P, B, S]) (PartialSignatureAggregator[P, B, S], error) {
	if utils.IsNil(curve) {
		return nil, cggmp21.ErrNil.WithMessage("curve")
	}
	return &offlineAggregator[P, B, S]{curve: curve}, nil
}

// Aggregate combines partial signatures without online signing session state.
func (a *offlineAggregator[P, B, S]) Aggregate(ps map[sharing.ID]*cggmp21.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if len(ps) == 0 {
		return nil, cggmp21.ErrNil.WithMessage("partial signatures")
	}

	var (
		gamma       P
		scalarField algebra.PrimeField[S]
		sig         S
		seen        bool
	)
	for id, psig := range ps {
		if psig == nil {
			return nil, cggmp21.ErrNil.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("partial signature for %d", id)
		}
		if err := validatePoint(psig.Gamma, "Gamma", false); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid Gamma in partial signature from %d", id)
		}
		if !a.curve.Contains(psig.Gamma) {
			return nil, cggmp21.ErrValidationFailed.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("Gamma in partial signature from %d does not belong to the configured curve", id)
		}
		if err := validateScalar(psig.Sigma, "Sigma", true); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid Sigma in partial signature from %d", id)
		}
		if !seen {
			var err error
			scalarField, err = algebra.StructureAs[algebra.PrimeField[S]](psig.Sigma.Structure())
			if err != nil {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid partial signature scalar structure from %d", id)
			}
			gamma = psig.Gamma.Clone()
			sig = scalarField.Zero()
			seen = true
		}
		if !gamma.Equal(psig.Gamma) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("Gamma mismatch in partial signature from %d", id)
		}
		sig = sig.Add(psig.Sigma)
	}
	rx, err := gamma.AffineX()
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot get Gamma affine x-coordinate")
	}
	r, err := scalarField.FromWideBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert Gamma x-coordinate to scalar")
	}
	v, err := sigecdsa.ComputeRecoveryID(gamma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute recovery ID")
	}

	signature, err := sigecdsa.NewSignature(r, sig, &v)
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot create ECDSA signature")
	}
	return signature, nil
}
