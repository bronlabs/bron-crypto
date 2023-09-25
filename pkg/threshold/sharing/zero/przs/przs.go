package przs

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const LambdaBytes = impl.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = map[types.IdentityHash]Seed

type Sample curves.Scalar
