package zero

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

const LambdaBytes = impl.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = map[helper_types.IdentityHash]Seed

type Sample curves.Scalar
