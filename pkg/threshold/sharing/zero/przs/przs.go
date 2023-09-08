package przs

import (
	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
)

const LambdaBytes = impl.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = map[helper_types.IdentityHash]Seed

type Sample curves.Scalar
