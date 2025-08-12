package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

func ComputePartialPublicKey[E GroupElement[E, S], S Scalar[S]](
	sf algebra.PrimeField[S],
	share *feldman.Share[S],
	vector feldman.VerificationVector[E, S],
	ac sharing.AccessStructure,
) (ds.Map[sharing.ID, E], error) {
	if share == nil {
		return nil, errs.NewIsNil("nil share")
	}
	if ac == nil {
		return nil, errs.NewIsNil("nil access structure")
	}
	if sf.Name() != share.Value().Structure().Name() {
		return nil, errs.NewType("field mismatch: %s != %s", sf.Name(), share.Value().Structure().Name())
	}
	out := hashmap.NewComparable[sharing.ID, E]()
	for id := range ac.Shareholders().Iter() {
		out.Put(
			id,
			vector.Eval(shamir.SharingIDToLagrangeNode(sf, id)),
		)
	}
	return out.Freeze(), nil
}
