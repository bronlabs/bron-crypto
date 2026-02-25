package przs

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

const (
	SeedLength = 32
)

// Seeds maps party identifiers to PRZS seed material.
type Seeds ds.Map[sharing.ID, [SeedLength]byte]
