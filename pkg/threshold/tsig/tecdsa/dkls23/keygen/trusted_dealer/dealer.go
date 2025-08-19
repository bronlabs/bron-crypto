package trusted_dealer

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
)

// TODO: adjust to the rest of whatever
func DealRandom[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], threshold uint, shareholder ds.Set[sharing.ID], prng io.Reader) (ds.Map[sharing.ID, *tecdsa.Shard[P, B, S]], P, error) {
	var nilP P

	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, nilP, errs.NewFailed("invalid scalar structure")
	}

	generator := curve.Generator()
	feldmanDealer, err := feldman.NewScheme(field, generator, threshold, shareholder)
	if err != nil {
		return nil, nilP, errs.WrapFailed(err, "could not create shamir scheme")
	}

	feldmanOutput, secret, err := feldmanDealer.DealRandom(prng)
	if err != nil {
		return nil, nilP, errs.WrapFailed(err, "could not deal shares")
	}
	public := generator.ScalarMul(secret.Value())

	result := hashmap.NewComparable[sharing.ID, *tecdsa.Shard[P, B, S]]()
	for id, feldmanShare := range feldmanOutput.Shares().Iter() {
		shard := tecdsa.NewShard(feldmanShare, public)
		result.Put(id, shard)
	}

	return result.Freeze(), public, nil
}
