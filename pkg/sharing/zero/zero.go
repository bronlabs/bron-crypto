package zero

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/native"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
)

const LambdaBytes = native.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = *hashmap.HashMap[integration.IdentityKey, Seed]

func NewPairwiseSeeds() PairwiseSeeds {
	return hashmap.NewHashMap[integration.IdentityKey, Seed]()
}

type Sample curves.Scalar
