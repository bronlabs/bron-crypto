package przs

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const LambdaBytes = constants.FieldBytes

type Seed = [LambdaBytes]byte

type PairwiseSeeds = map[types.IdentityHash]Seed

type Sample curves.Scalar
