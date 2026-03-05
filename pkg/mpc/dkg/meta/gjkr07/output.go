package gjkr07

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

func NewDKGOutput[
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	S sharing.LinearShare[S, SV],
	SV algebra.PrimeFieldElement[SV],
	AC accessstructures.Monotone,
](
	share S,
	vector LFTDF,
	accessStructure AC,
) (*DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC], error) {
	if utils.IsNil(share) {
		return nil, ErrInvalidArgument.WithMessage("share cannot be nil")
	}
	if utils.IsNil(vector) {
		return nil, ErrInvalidArgument.WithMessage("verification vector cannot be nil")
	}
	if utils.IsNil(accessStructure) {
		return nil, ErrInvalidArgument.WithMessage("access structure cannot be nil")
	}
	publicKey := vector.Basis()
	out := hashmap.NewComparable[sharing.ID, LFTS]()
	for id := range accessStructure.Shareholders().Iter() {
		out.Put(
			id,
			vector.ShareOf(id),
		)
	}
	return &DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]{
		share: share,
		DKGPublicOutput: DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC]{
			publicKeyValue:    publicKey,
			partialPublicKeys: nil,
			fv:                vector,
			accessStructure:   accessStructure,
		},
	}, nil
}

type DKGOutput[
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	S sharing.LinearShare[S, SV],
	SV algebra.PrimeFieldElement[SV],
	AC accessstructures.Monotone,
] struct {
	share S
	DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC]
}

func (d *DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]) Share() S {
	return d.share
}

func (d *DKGOutput[LFTDF, LFTS, LFTSV, S, SV, AC]) PublicMaterial() *DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC] {
	return &DKGPublicOutput[
		LFTDF, LFTS, LFTSV, SV, AC,
	]{
		publicKeyValue:    d.publicKeyValue,
		partialPublicKeys: d.partialPublicKeys,
		fv:                d.fv,
		accessStructure:   d.accessStructure,
	}
}

type DKGPublicOutput[
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	SV algebra.PrimeFieldElement[SV],
	AC accessstructures.Monotone,
] struct {
	publicKeyValue    LFTSV
	partialPublicKeys ds.Map[sharing.ID, LFTS]
	fv                LFTDF
	accessStructure   AC
}

func (d *DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC]) PublicKeyValue() LFTSV {
	return d.publicKeyValue
}

func (d *DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC]) PartialPublicKeys() ds.Map[sharing.ID, LFTS] {
	return d.partialPublicKeys
}

func (d *DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC]) VerificationVector() LFTDF {
	return d.fv
}

func (d *DKGPublicOutput[LFTDF, LFTS, LFTSV, SV, AC]) AccessStructure() AC {
	return d.accessStructure
}
