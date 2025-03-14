package rprzs

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

const LambdaBytes = base.CollisionResistanceBytes

type (
	Seed          = [LambdaBytes]byte
	PairWiseSeeds ds.Map[types.IdentityKey, Seed]
	Sample        curves.Scalar
)
