package rprzs

import (
	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
)

const LambdaBytes = base.CollisionResistanceBytes

type (
	Seed          = [LambdaBytes]byte
	PairWiseSeeds ds.Map[types.IdentityKey, Seed]
	Sample        curves.Scalar
)
