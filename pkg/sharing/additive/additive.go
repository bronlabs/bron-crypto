package additive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
)

type Share struct {
	Value curves.Scalar `json:"value"`
}

// Converts len(identities) many additive shares into a (t, n) shamir scheme. An `id`
// is a shamir concept, and the holder of the additive share may have different ids for different
// shamir configs.
// In case after conversion, resharing of the new shamir share is desired. A new protocol must
// be implemented where it runs the Pedersen DKG with a_i0 = Share.Value.
func (s Share) ConvertToShamir(id, t, n int, identities []int) (*shamir.Share, error) {
	curve, err := curves.GetCurveByName(s.Value.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not fetch curve by name")
	}
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
	Curve *curves.Curve
}

func NewDealer(total int, curve *curves.Curve) (*Dealer, error) {
	if total < 2 {
		return nil, errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if curve == nil {
		return nil, errs.NewIsNil("invalid curve")
	}
	return &Dealer{total, curve}, nil
}

func (d Dealer) Split(secret curves.Scalar, prng io.Reader) ([]*Share, error) {
	if secret.IsZero() {
		return nil, errs.NewIsZero("invalid secret")
	}
	shares := make([]*Share, d.Total)
	partialSum := d.Curve.Scalar.Zero()
	for i := 1; i < d.Total; i++ {
		share := d.Curve.Scalar.Random(prng)
		partialSum = partialSum.Add(share)
		shares[i] = &Share{share}
	}
	shares[0] = &Share{secret.Sub(partialSum)}
	return shares, nil
}

func (d Dealer) Combine(shares []*Share) (curves.Scalar, error) {
	if len(shares) != d.Total {
		return nil, errs.NewFailed("len(shares) != N")
	}
	secret := d.Curve.Scalar.Zero()
	for _, share := range shares {
		if share == nil || share.Value.IsZero() {
			return nil, errs.NewIsZero("found a share with value %d", share.Value.BigInt())
		}
		secret = secret.Add(share.Value)
	}
	return secret, nil
}
