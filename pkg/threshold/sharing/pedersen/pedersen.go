package pedersen_vss

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ecpedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

//var (
//	_ sharing.Share                                                                                      = (*Share)(nil)
//	_ sharing.LinearVerifiableScheme[*Share, curves.Scalar, curves.Scalar, []ecpedersen_comm.Commitment] = (*Scheme)(nil)
//)

type Share[S fields.PrimeFieldElement[S]] struct {
	ShamirShare *shamir.Share[S]
	Witness     *ecpedersen_comm.Witness[S]
}

func (s *Share[S]) SharingId() types.SharingID {
	return s.ShamirShare.Id
}

type Scheme[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	Curve            C
	Ck               *ecpedersen_comm.CommittingKey[P, F, S]
	Threshold, Total uint
}

func NewScheme[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](curve C, ck *ecpedersen_comm.CommittingKey[P, F, S], threshold, total uint) (scheme *Scheme[C, P, F, S], err error) {
	if ck == nil {
		return nil, errs.NewIsNil("ck")
	}
	if threshold < 2 || threshold > total || total < 2 {
		return nil, errs.NewValidation("invalid access structure")
	}

	return &Scheme[C, P, F, S]{
		Curve:     curve,
		Ck:        ck,
		Threshold: threshold,
		Total:     total,
	}, nil
}

func (d *Scheme[C, P, F, S]) DealWithPolynomial(secret S, prng io.Reader) (shares map[types.SharingID]*Share[S], polynomial []S, verificationVector []*ecpedersen_comm.Commitment[P, F, S], err error) {
	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, d.Curve.ScalarField())
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	shamirShares, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}

	verificationVector = make([]*ecpedersen_comm.Commitment[P, F, S], len(poly.Coefficients))
	witnessCoefficients := make([]*ecpedersen_comm.Witness[S], len(poly.Coefficients))
	for i, c := range poly.Coefficients {
		verificationVector[i], witnessCoefficients[i], err = d.Ck.Commit(ecpedersen_comm.NewMessage(c), prng)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not commit to coefficient")
		}
	}

	witnesses := make(map[types.SharingID]*ecpedersen_comm.Witness[S])
	for sharingId := range shamirShares {
		x := types.SharingIDToScalar(sharingId, d.Curve.ScalarField())
		witnesses[sharingId], err = evalPolyAt(witnessCoefficients, x, d.Ck.WitnessAdd, d.Ck.WitnessMul)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not evaluate polynomial and shares")
		}
	}

	shares = make(map[types.SharingID]*Share[S])
	for sharingId, share := range shamirShares {
		shares[sharingId] = &Share[S]{
			ShamirShare: &shamir.Share[S]{
				Id:    share.Id,
				Value: share.Value,
			},
			Witness: witnesses[sharingId],
		}
	}

	return shares, poly.Coefficients, verificationVector, nil
}

func (d *Scheme[C, P, F, S]) DealVerifiable(secret S, prng io.Reader) (shares map[types.SharingID]*Share[S], verificationVector []*ecpedersen_comm.Commitment[P, F, S], err error) {
	shares, _, verificationVector, err = d.DealWithPolynomial(secret, prng)
	return shares, verificationVector, err
}

func (d *Scheme[C, P, F, S]) Deal(secret S, prng io.Reader) (shares map[types.SharingID]*Share[S], err error) {
	shares, _, err = d.DealVerifiable(secret, prng)
	return shares, err
}

func (d *Scheme[C, P, F, S]) VerifyShare(share *Share[S], verificationVector []*ecpedersen_comm.Commitment[P, F, S]) error {
	if len(verificationVector) != int(d.Threshold) {
		return errs.NewFailed("invalid commitment vector")
	}
	if share.SharingId() < 1 || uint(share.SharingId()) > d.Total {
		return errs.NewFailed("invalid sharing id")
	}

	x := types.SharingIDToScalar(share.ShamirShare.Id, d.Curve.ScalarField())
	y, err := evalPolyAt(verificationVector, x, d.Ck.CommitmentAdd, d.Ck.CommitmentMul)
	if err != nil {
		return errs.WrapFailed(err, "cannot evaluate polynomial")
	}

	err = d.Ck.Verify(y, ecpedersen_comm.NewMessage(share.ShamirShare.Value), share.Witness)
	if err != nil {
		return errs.NewFailed("invalid share")
	}

	return nil
}

func (d *Scheme[C, P, F, S]) Open(shares ...*Share[S]) (S, error) {
	var nilS S

	if len(shares) < 2 {
		return nilS, errs.NewFailed("invalid shares")
	}

	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, d.Curve.ScalarField())
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not combine shares")
	}

	shamirShares := slices.Collect(iterutils.Map(slices.Values(shares), func(s *Share[S]) *shamir.Share[S] { return s.ShamirShare }))
	result, err := shamirDealer.Open(shamirShares...)
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not combine shares")
	}

	return result, nil
}

func (d *Scheme[C, P, F, S]) ShareAdd(lhs, rhs *Share[S]) *Share[S] {
	v, _ := d.Ck.MessageAdd(ecpedersen_comm.NewMessage(lhs.ShamirShare.Value), ecpedersen_comm.NewMessage(rhs.ShamirShare.Value))
	w, _ := d.Ck.WitnessAdd(lhs.Witness, rhs.Witness)

	return &Share[S]{
		ShamirShare: &shamir.Share[S]{
			Id:    lhs.ShamirShare.Id,
			Value: v.M,
		},
		Witness: w,
	}
}

func (d *Scheme[C, P, F, S]) ShareAddValue(lhs *Share[S], rhs S) *Share[S] {
	v, _ := d.Ck.MessageAdd(ecpedersen_comm.NewMessage(lhs.ShamirShare.Value), ecpedersen_comm.NewMessage(rhs))

	return &Share[S]{
		ShamirShare: &shamir.Share[S]{
			Id:    lhs.ShamirShare.Id,
			Value: v.M,
		},
		Witness: lhs.Witness,
	}
}

func (d *Scheme[C, P, F, S]) ShareSub(lhs, rhs *Share[S]) *Share[S] {
	v, _ := d.Ck.MessageSub(ecpedersen_comm.NewMessage(lhs.ShamirShare.Value), ecpedersen_comm.NewMessage(rhs.ShamirShare.Value))
	w, _ := d.Ck.WitnessSub(lhs.Witness, rhs.Witness)

	return &Share[S]{
		ShamirShare: &shamir.Share[S]{
			Id:    lhs.ShamirShare.Id,
			Value: v.M,
		},
		Witness: w,
	}
}

func (d *Scheme[C, P, F, S]) ShareSubValue(lhs *Share[S], rhs S) *Share[S] {
	v, _ := d.Ck.MessageSub(ecpedersen_comm.NewMessage(lhs.ShamirShare.Value), ecpedersen_comm.NewMessage(rhs))

	return &Share[S]{
		ShamirShare: &shamir.Share[S]{
			Id:    lhs.ShamirShare.Id,
			Value: v.M,
		},
		Witness: lhs.Witness,
	}
}

func (d *Scheme[C, P, F, S]) ShareNeg(lhs *Share[S]) *Share[S] {
	v, _ := d.Ck.MessageNeg(ecpedersen_comm.NewMessage(lhs.ShamirShare.Value))
	w, _ := d.Ck.WitnessNeg(lhs.Witness)

	return &Share[S]{
		ShamirShare: &shamir.Share[S]{
			Id:    lhs.ShamirShare.Id,
			Value: v.M,
		},
		Witness: w,
	}
}

func (d *Scheme[C, P, F, S]) ShareMul(lhs *Share[S], rhs S) *Share[S] {
	v, _ := d.Ck.MessageMul(ecpedersen_comm.NewMessage(lhs.ShamirShare.Value), rhs)
	w, _ := d.Ck.WitnessMul(lhs.Witness, rhs)

	return &Share[S]{
		ShamirShare: &shamir.Share[S]{
			Id:    lhs.ShamirShare.Id,
			Value: v.M,
		},
		Witness: w,
	}
}

func (d *Scheme[C, P, F, S]) VerificationAdd(lhs, rhs []*ecpedersen_comm.Commitment[P, F, S]) []*ecpedersen_comm.Commitment[P, F, S] {
	v := make([]*ecpedersen_comm.Commitment[P, F, S], len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		v[i], _ = d.Ck.CommitmentAdd(l, r)
	}

	return v
}

func (d *Scheme[C, P, F, S]) VerificationAddValue(lhs []*ecpedersen_comm.Commitment[P, F, S], rhs S) []*ecpedersen_comm.Commitment[P, F, S] {
	v := make([]*ecpedersen_comm.Commitment[P, F, S], len(lhs))
	for i, l := range lhs {
		if i == 0 {
			v[i], _ = d.Ck.CommitmentAddMessage(l, ecpedersen_comm.NewMessage(rhs))
		} else {
			v[i] = l
		}
	}

	return v
}

func (d *Scheme[C, P, F, S]) VerificationSub(lhs, rhs []*ecpedersen_comm.Commitment[P, F, S]) []*ecpedersen_comm.Commitment[P, F, S] {
	v := make([]*ecpedersen_comm.Commitment[P, F, S], len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		v[i], _ = d.Ck.CommitmentSub(l, r)
	}

	return v
}

func (d *Scheme[C, P, F, S]) VerificationSubValue(lhs []*ecpedersen_comm.Commitment[P, F, S], rhs S) []*ecpedersen_comm.Commitment[P, F, S] {
	v := make([]*ecpedersen_comm.Commitment[P, F, S], len(lhs))
	for i, l := range lhs {
		if i == 0 {
			v[i], _ = d.Ck.CommitmentSubMessage(l, ecpedersen_comm.NewMessage(rhs))
		} else {
			v[i] = l
		}
	}

	return v
}

func (d *Scheme[C, P, F, S]) VerificationNeg(lhs []*ecpedersen_comm.Commitment[P, F, S]) []*ecpedersen_comm.Commitment[P, F, S] {
	v := make([]*ecpedersen_comm.Commitment[P, F, S], len(lhs))
	for i, l := range lhs {
		v[i], _ = d.Ck.CommitmentNeg(l)
	}

	return v
}

func (d *Scheme[C, P, F, S]) VerificationMul(lhs []*ecpedersen_comm.Commitment[P, F, S], rhs S) []*ecpedersen_comm.Commitment[P, F, S] {
	v := make([]*ecpedersen_comm.Commitment[P, F, S], len(lhs))
	for i, l := range lhs {
		v[i], _ = d.Ck.CommitmentMul(l, rhs)
	}

	return v
}

func evalPolyAt[Y any, X any](poly []Y, at X, addFunc func(lhs, rhs Y) (Y, error), mulFunc func(lhs Y, rhs X) (Y, error)) (Y, error) {
	result := poly[len(poly)-1]
	for i := len(poly) - 2; i >= 0; i-- {
		var err error
		result, err = mulFunc(result, at)
		if err != nil {
			return *new(Y), errs.WrapFailed(err, "cannot perform multiplication")
		}
		result, err = addFunc(result, poly[i])
		if err != nil {
			return *new(Y), errs.WrapFailed(err, "cannot perform addition")
		}
	}

	return result, nil
}
