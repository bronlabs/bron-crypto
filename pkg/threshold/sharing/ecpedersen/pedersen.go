package ecpedersen_vss

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ecpedersen_comm "github.com/copperexchange/krypton-primitives/pkg/commitments/ecpedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"io"
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
	ck               *ecpedersen_comm.CommittingKey
	threshold, total uint
}

func NewDealer(ck *ecpedersen_comm.CommittingKey, threshold, total uint) *Dealer {
	return &Dealer{
		ck:        ck,
		threshold: threshold,
		total:     total,
	}
}

func (d *Dealer) Deal(secret ecpedersen_comm.Message, prng io.Reader) (shares map[types.SharingID]*Share, commitments []ecpedersen_comm.Commitment, err error) {
	messages := make([]ecpedersen_comm.Message, d.threshold)
	commitments = make([]ecpedersen_comm.Commitment, d.threshold)
	witnesses := make([]ecpedersen_comm.Witness, d.threshold)

	scalarField := secret.ScalarField()
	for i := range d.threshold {
		if i == 0 {
			messages[i] = secret.Clone()
		} else {
			messages[i], err = scalarField.Random(prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
			}
		}
		commitments[i], witnesses[i], err = d.ck.Commit(messages[i], prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot commit to scalar")
		}
	}

	shares = make(map[types.SharingID]*Share)
	for i := range d.total {
		sharingId := types.SharingID(i + 1)
		at := scalarField.New(uint64(sharingId))
		value, err := evalPolyAt(messages, ecpedersen_comm.Scalar(at), d.ck.MessageAdd, d.ck.MessageMul)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot evaluate poly")
		}
		witness, err := evalPolyAt(witnesses, ecpedersen_comm.Scalar(at), d.ck.WitnessAdd, d.ck.WitnessMul)
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

func (d *Dealer) VerifyReveal(commitments []ecpedersen_comm.Commitment, shares ...*Share) (ecpedersen_comm.Message, error) {
	if len(shares) < int(d.threshold) {
		return nil, errs.NewSize("invalid number of shares")
	}
	dups := make(map[uint]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Scalar, len(shares))
	rs := make([]curves.Scalar, len(shares))

	for i, share := range shares {
		if share.Id > d.total {
			return nil, errs.NewValue("invalid share identifier id: %d must be greater than total: %d", share.Id, d.total)
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

	err = d.ck.Verify(commitments[0], message, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "verification failed")
	}
	return message, nil
}

func (d *Dealer) VerifyShare(share *Share, commitments []ecpedersen_comm.Commitment) error {
	at := share.Value.ScalarField().New(uint64(share.Id))
	commitment, err := evalPolyAt(commitments, ecpedersen_comm.Scalar(at), d.ck.CommitmentAdd, d.ck.CommitmentMul)
	if err != nil {
		return errs.NewVerification("cannot verify share")
	}
	return d.ck.Verify(commitment, share.Value, share.R)
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
