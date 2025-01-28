package ecpedersen_vss

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ecpedersen_comm "github.com/bronlabs/krypton-primitives/pkg/commitments/ecpedersen"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
)

type ShamirShare = shamir.Share

type Share struct {
	ShamirShare
	R ecpedersen_comm.Witness
}

func (s *Share) ToOpening() *ecpedersen_comm.Opening {
	return ecpedersen_comm.NewOpening(s.ShamirShare.Value, s.R)
}

func (s *Share) AsShamir() *shamir.Share {
	return &s.ShamirShare
}

type Dealer struct {
	Ck               *ecpedersen_comm.CommittingKey
	Threshold, Total uint
}

func NewDealer(ck *ecpedersen_comm.CommittingKey, threshold, total uint) *Dealer {
	return &Dealer{
		Ck:        ck,
		Threshold: threshold,
		Total:     total,
	}
}

func (d *Dealer) DealPolynomial(secretPolynomial []curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, commitments []ecpedersen_comm.Commitment, err error) {
	if len(secretPolynomial) != int(d.Threshold) {
		return nil, nil, errs.NewSize("invalid polynomial length")
	}

	messages := make([]ecpedersen_comm.Message, d.Threshold)
	commitments = make([]ecpedersen_comm.Commitment, d.Threshold)
	witnesses := make([]ecpedersen_comm.Witness, d.Threshold)

	scalarField := secretPolynomial[0].ScalarField()
	for i := range d.Threshold {
		messages[i] = secretPolynomial[i]
		commitments[i], witnesses[i], err = d.Ck.Commit(messages[i], prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot commit to scalar")
		}
	}

	shares = make(map[types.SharingID]*Share)
	for i := range d.Total {
		sharingId := types.SharingID(i + 1)
		at := scalarField.New(uint64(sharingId))
		value, err := evalPolyAt(messages, ecpedersen_comm.Scalar(at), d.Ck.MessageAdd, d.Ck.MessageMul)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot evaluate poly")
		}
		witness, err := evalPolyAt(witnesses, ecpedersen_comm.Scalar(at), d.Ck.WitnessAdd, d.Ck.WitnessMul)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot evaluate poly")
		}

		shares[sharingId] = &Share{
			ShamirShare: shamir.Share{
				Id:    uint(sharingId),
				Value: value,
			},
			R: witness,
		}
	}

	return shares, commitments, nil
}

func (d *Dealer) Deal(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, commitments []ecpedersen_comm.Commitment, secretPolynomial []curves.Scalar, err error) {
	scalarField := secret.ScalarField()
	secretPolynomial = make([]curves.Scalar, d.Threshold)
	secretPolynomial[0] = secret.Clone()
	for i := 1; i < int(d.Threshold); i++ {
		secretPolynomial[i], err = scalarField.Random(prng)
		if err != nil {
			return nil, nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
		}
	}

	shares, commitments, err = d.DealPolynomial(secretPolynomial, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "cannot deal with polynomial")
	}
	return shares, commitments, secretPolynomial, nil
}

func (d *Dealer) VerifyReveal(commitments []ecpedersen_comm.Commitment, shares ...*Share) (ecpedersen_comm.Message, error) {
	if len(commitments) != int(d.Threshold) {
		return nil, errs.NewSize("invalid length of commitment vector")
	}
	if len(shares) < int(d.Threshold) {
		return nil, errs.NewSize("invalid number of shares")
	}
	dups := make(map[uint]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Scalar, len(shares))
	rs := make([]curves.Scalar, len(shares))

	for i, share := range shares {
		if share.Id > d.Total {
			return nil, errs.NewValue("invalid share identifier id: %d must be greater than total: %d", share.Id, d.Total)
		}
		if err := d.VerifyShare(share, commitments); err != nil {
			return nil, errs.NewValue("invalid share")
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewMembership("duplicate share")
		}
		dups[share.Id] = true
		ys[i] = share.Value
		rs[i] = share.R
		xs[i] = share.Value.ScalarField().New(uint64(share.Id))
	}
	curve := shares[0].Value.ScalarField().Curve()
	message, err := lagrange.Interpolate(curve, xs, ys, curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}
	witness, err := lagrange.Interpolate(curve, xs, rs, curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}

	err = d.Ck.Verify(commitments[0], message, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "verification failed")
	}
	return message, nil
}

func (d *Dealer) VerifyShare(share *Share, commitments []ecpedersen_comm.Commitment) error {
	at := share.Value.ScalarField().New(uint64(share.Id))
	commitment, err := evalPolyAt(commitments, ecpedersen_comm.Scalar(at), d.Ck.CommitmentAdd, d.Ck.CommitmentMul)
	if err != nil {
		return errs.WrapVerification(err, "cannot verify share")
	}
	err = d.Ck.Verify(commitment, share.Value, share.R)
	if err != nil {
		return errs.WrapVerification(err, "cannot verify share")
	}

	return nil
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
