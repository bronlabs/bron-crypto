package additive

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Share struct {
	_ types.Incomparable

	Value curves.Scalar `json:"value"`
}

// ConvertToShamir converts len(identities) many additive shares into a (t, n) shamir scheme. An `id`
// is a shamir concept, and the holder of the additive share may have different ids for different
// shamir configs.
// In case after conversion, resharing of the new shamir share is desired. A new protocol must
// be implemented where it runs the Pedersen DKG with a_i0 = Share.Value.
func (s Share) ConvertToShamir(id, t, n int, identities []int) (*shamir.Share, error) {
	curve := s.Value.Curve()
	shamirDealer, err := shamir.NewDealer(t, n, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct shamir share")
	}
	coefficients, err := shamirDealer.LagrangeCoefficients(identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	myCoefficient, exists := coefficients[id]
	if !exists {
		return nil, errs.NewMissing("i am not one of the provided identities")
	}
	return &shamir.Share{
		Id:    id,
		Value: s.Value.Div(myCoefficient),
	}, nil
}

type Dealer struct {
	Total int
	Curve curves.Curve

	_ types.Incomparable
}

func NewDealer(total int, curve curves.Curve) (*Dealer, error) {
	dealer := &Dealer{Total: total, Curve: curve}
	if err := dealer.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid additive sharing dealer")
	}
	return dealer, nil
}

func (d *Dealer) Validate() error {
	if d == nil {
		return errs.NewIsNil("dealer is nil")
	}
	if d.Total < 2 {
		return errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if d.Curve == nil {
		return errs.NewIsNil("invalid curve")
	}
	return nil
}

func (d *Dealer) Split(secret curves.Scalar, prng io.Reader) ([]*Share, error) {
	if secret.IsZero() {
		return nil, errs.NewIsZero("invalid secret")
	}
	shares := make([]*Share, d.Total)
	partialSum := d.Curve.Scalar().Zero()
	for i := 1; i < d.Total; i++ {
		share, err := d.Curve.Scalar().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
		}
		partialSum = partialSum.Add(share)
		shares[i] = &Share{Value: share}
	}
	shares[0] = &Share{Value: secret.Sub(partialSum)}
	return shares, nil
}

func (d *Dealer) Combine(shares []*Share) (curves.Scalar, error) {
	if len(shares) != d.Total {
		return nil, errs.NewFailed("len(shares) != N")
	}
	secret := d.Curve.Scalar().Zero()
	for _, share := range shares {
		if share == nil || share.Value.IsZero() {
			return nil, errs.NewIsZero("found a share with value %s", share.Value.Nat().String())
		}
		secret = secret.Add(share.Value)
	}
	return secret, nil
}
