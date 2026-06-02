package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func AggregateOffline[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](partialSignatures ...*cggmp21.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if len(partialSignatures) == 0 {
		return nil, cggmp21.ErrNil.WithMessage("partial signatures")
	}
	if partialSignatures[0] == nil {
		return nil, cggmp21.ErrNil.WithMessage("partial signature")
	}
	if err := validatePoint(partialSignatures[0].Gamma, "Gamma", false); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid Gamma in partial signature")
	}
	if err := validateScalar(partialSignatures[0].Sigma, "Sigma", true); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid Sigma in partial signature")
	}
	scalarField, err := algebra.StructureAs[algebra.PrimeField[S]](partialSignatures[0].Sigma.Structure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid partial signature scalar structure")
	}
	gamma := partialSignatures[0].Gamma.Clone()
	sig := scalarField.Zero()
	for i, psig := range partialSignatures {
		if psig == nil {
			return nil, cggmp21.ErrNil.WithMessage("partial signature at index %d", i)
		}
		if err := validatePoint(psig.Gamma, "Gamma", false); err != nil {
			return nil, errs.Wrap(err).WithMessage("invalid Gamma in partial signature at index %d", i)
		}
		if err := validateScalar(psig.Sigma, "Sigma", true); err != nil {
			return nil, errs.Wrap(err).WithMessage("invalid Sigma in partial signature at index %d", i)
		}
		if !gamma.Equal(psig.Gamma) {
			return nil, base.ErrAbort.WithMessage("partial signatures have inconsistent Gamma values")
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
