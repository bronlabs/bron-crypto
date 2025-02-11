package pedersen_vss

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/sliceutils"
	ecpedersen_comm "github.com/bronlabs/krypton-primitives/pkg/commitments/pedersen"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
)

var (
	_ sharing.Share                                                                                      = (*Share)(nil)
	_ sharing.LinearVerifiableScheme[*Share, curves.Scalar, curves.Scalar, []ecpedersen_comm.Commitment] = (*Scheme)(nil)
)

type Share struct {
	ShamirShare shamir.Share
	Witness     ecpedersen_comm.Witness
}

func (s *Share) SharingId() types.SharingID {
	return s.ShamirShare.Id
}

type Scheme struct {
	Ck               *ecpedersen_comm.CommittingKey
	Threshold, Total uint
}

func NewScheme(ck *ecpedersen_comm.CommittingKey, threshold, total uint) *Scheme {
	return &Scheme{
		Ck:        ck,
		Threshold: threshold,
		Total:     total,
	}
}

func (d *Scheme) DealWithPolynomial(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, polynomial []curves.Scalar, verificationVector []ecpedersen_comm.Commitment, err error) {
	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, secret.ScalarField().Curve())
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	shamirShares, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}

	verificationVector = make([]ecpedersen_comm.Commitment, len(poly.Coefficients))
	witnessCoefficients := make([]ecpedersen_comm.Witness, len(poly.Coefficients))
	for i, c := range poly.Coefficients {
		verificationVector[i], witnessCoefficients[i], err = d.Ck.Commit(c, prng)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not commit to coefficient")
		}
	}

	witnesses := make(map[types.SharingID]ecpedersen_comm.Witness)
	for sharingId := range shamirShares {
		x := sharingId.ToScalar(secret.ScalarField())
		witnesses[sharingId], err = evalPolyAt(witnessCoefficients, ecpedersen_comm.Scalar(x), d.Ck.WitnessAdd, d.Ck.WitnessMul)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not evaluate polynomial and shares")
		}
	}

	shares = make(map[types.SharingID]*Share)
	for sharingId, share := range shamirShares {
		shares[sharingId] = &Share{
			ShamirShare: shamir.Share{
				Id:    share.Id,
				Value: share.Value,
			},
			Witness: witnesses[sharingId],
		}
	}

	return shares, poly.Coefficients, verificationVector, nil
}

func (d *Scheme) DealVerifiable(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, verificationVector []ecpedersen_comm.Commitment, err error) {
	shares, _, verificationVector, err = d.DealWithPolynomial(secret, prng)
	return shares, verificationVector, err
}

func (d *Scheme) Deal(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, err error) {
	shares, _, err = d.DealVerifiable(secret, prng)
	return shares, err
}

func (d *Scheme) VerifyShare(share *Share, verificationVector []ecpedersen_comm.Commitment) error {
	if len(verificationVector) != int(d.Threshold) {
		return errs.NewFailed("invalid commitment vector")
	}
	if share.SharingId() < 1 || uint(share.SharingId()) > d.Total {
		return errs.NewFailed("invalid sharing id")
	}

	x := share.ShamirShare.Id.ToScalar(share.ShamirShare.Value.ScalarField())
	y, err := evalPolyAt(verificationVector, ecpedersen_comm.Scalar(x), d.Ck.CommitmentAdd, d.Ck.CommitmentMul)
	if err != nil {
		return errs.WrapFailed(err, "cannot evaluate polynomial")
	}

	err = d.Ck.Verify(y, share.ShamirShare.Value, share.Witness)
	if err != nil {
		return errs.NewFailed("invalid share")
	}

	return nil
}

func (d *Scheme) Open(shares ...*Share) (curves.Scalar, error) {
	if len(shares) < 2 {
		return nil, errs.NewFailed("invalid shares")
	}

	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, shares[0].ShamirShare.Value.ScalarField().Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine shares")
	}

	shamirShares := sliceutils.Map(shares, func(s *Share) *shamir.Share { return &s.ShamirShare })
	result, err := shamirDealer.Open(shamirShares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine shares")
	}

	return result, nil
}

func (d *Scheme) ShareAdd(lhs, rhs *Share) *Share {
	v, _ := d.Ck.MessageAdd(lhs.ShamirShare.Value, rhs.ShamirShare.Value)
	w, _ := d.Ck.WitnessAdd(lhs.Witness, rhs.Witness)

	return &Share{
		ShamirShare: shamir.Share{
			Id:    lhs.ShamirShare.Id,
			Value: v,
		},
		Witness: w,
	}
}

func (d *Scheme) ShareAddValue(lhs *Share, rhs curves.Scalar) *Share {
	v, _ := d.Ck.MessageAdd(lhs.ShamirShare.Value, rhs)

	return &Share{
		ShamirShare: shamir.Share{
			Id:    lhs.ShamirShare.Id,
			Value: v,
		},
		Witness: lhs.Witness,
	}
}

func (d *Scheme) ShareSub(lhs, rhs *Share) *Share {
	v, _ := d.Ck.MessageSub(lhs.ShamirShare.Value, rhs.ShamirShare.Value)
	w, _ := d.Ck.WitnessSub(lhs.Witness, rhs.Witness)

	return &Share{
		ShamirShare: shamir.Share{
			Id:    lhs.ShamirShare.Id,
			Value: v,
		},
		Witness: w,
	}
}

func (d *Scheme) ShareSubValue(lhs *Share, rhs curves.Scalar) *Share {
	v, _ := d.Ck.MessageSub(lhs.ShamirShare.Value, rhs)

	return &Share{
		ShamirShare: shamir.Share{
			Id:    lhs.ShamirShare.Id,
			Value: v,
		},
		Witness: lhs.Witness,
	}
}

func (d *Scheme) ShareNeg(lhs *Share) *Share {
	v, _ := d.Ck.MessageNeg(lhs.ShamirShare.Value)
	w, _ := d.Ck.WitnessNeg(lhs.Witness)

	return &Share{
		ShamirShare: shamir.Share{
			Id:    lhs.ShamirShare.Id,
			Value: v,
		},
		Witness: w,
	}
}

func (d *Scheme) ShareMul(lhs *Share, rhs curves.Scalar) *Share {
	v, _ := d.Ck.MessageMul(lhs.ShamirShare.Value, rhs)
	w, _ := d.Ck.WitnessMul(lhs.Witness, rhs)

	return &Share{
		ShamirShare: shamir.Share{
			Id:    lhs.ShamirShare.Id,
			Value: v,
		},
		Witness: w,
	}
}

func (d *Scheme) VerificationAdd(lhs, rhs []ecpedersen_comm.Commitment) []ecpedersen_comm.Commitment {
	v := make([]ecpedersen_comm.Commitment, len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		v[i], _ = d.Ck.CommitmentAdd(l, r)
	}

	return v
}

func (d *Scheme) VerificationAddValue(lhs []ecpedersen_comm.Commitment, rhs curves.Scalar) []ecpedersen_comm.Commitment {
	v := make([]ecpedersen_comm.Commitment, len(lhs))
	for i, l := range lhs {
		v[i], _ = d.Ck.CommitmentAddMessage(l, rhs)
	}

	return v
}

func (d *Scheme) VerificationSub(lhs, rhs []ecpedersen_comm.Commitment) []ecpedersen_comm.Commitment {
	v := make([]ecpedersen_comm.Commitment, len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		v[i], _ = d.Ck.CommitmentSub(l, r)
	}

	return v
}

func (d *Scheme) VerificationSubValue(lhs []ecpedersen_comm.Commitment, rhs curves.Scalar) []ecpedersen_comm.Commitment {
	v := make([]ecpedersen_comm.Commitment, len(lhs))
	for i, l := range lhs {
		v[i], _ = d.Ck.CommitmentSubMessage(l, rhs)
	}

	return v
}

func (d *Scheme) VerificationNeg(lhs []ecpedersen_comm.Commitment) []ecpedersen_comm.Commitment {
	v := make([]ecpedersen_comm.Commitment, len(lhs))
	for i, l := range lhs {
		v[i], _ = d.Ck.CommitmentNeg(l)
	}

	return v
}

func (d *Scheme) VerificationMul(lhs []ecpedersen_comm.Commitment, rhs curves.Scalar) []ecpedersen_comm.Commitment {
	v := make([]ecpedersen_comm.Commitment, len(lhs))
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
