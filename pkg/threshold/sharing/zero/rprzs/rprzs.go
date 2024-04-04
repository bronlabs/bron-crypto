package rprzs

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const LambdaBytes = base.CollisionResistanceBytes

type (
	Seed          = [LambdaBytes]byte
	PairWiseSeeds ds.Map[types.IdentityKey, Seed]
	Sample        curves.Scalar
)
