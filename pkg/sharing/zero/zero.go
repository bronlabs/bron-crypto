package zero

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

const LambdaBytes = native.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = map[integration.IdentityKey]Seed

type Sample curves.Scalar
