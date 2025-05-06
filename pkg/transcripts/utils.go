package transcripts

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func AppendScalar[S fields.PrimeFieldElement[S]](tape Transcript, label string, scalar S) {
	scalarBytes := scalar.Bytes()
	tape.AppendBytes(label, scalarBytes)
}

func ExtractScalar[SF fields.PrimeField[S], S fields.PrimeFieldElement[S]](tape Transcript, label string, scalarField SF) (S, error) {
	var sNil S
	scalarWideLen := scalarField.WideElementSize()
	scalarWideBytes, err := tape.ExtractBytes(label, uint(scalarWideLen))
	if err != nil {
		return sNil, errs.WrapFailed(err, "could not extract scalar from transcript")
	}
	scalar, err := scalarField.FromWideBytes(scalarWideBytes)
	if err != nil {
		return sNil, errs.WrapFailed(err, "could not extract scalar from transcript")
	}

	return scalar, nil
}

func AppendPoint[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tape Transcript, label string, point P) {
	pointBytes := point.ToAffineCompressed()
	tape.AppendBytes(label, pointBytes)
}

func ExtractPoint[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tape Transcript, label string, curve C) (P, error) {
	var pNil P
	pointLen := curve.BaseField().WideElementSize()
	pointWideBytes, err := tape.ExtractBytes(label, uint(pointLen))
	if err != nil {
		return pNil, errs.WrapFailed(err, "could not extract point from transcript")
	}
	point, err := curve.Hash(pointWideBytes)
	if err != nil {
		return pNil, errs.WrapFailed(err, "could not extract point from transcript")
	}

	return point, nil
}
