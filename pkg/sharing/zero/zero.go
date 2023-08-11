package zero

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/native"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
)

const LambdaBytes = native.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = map[integration.IdentityKey]Seed

type Sample curves.Scalar
