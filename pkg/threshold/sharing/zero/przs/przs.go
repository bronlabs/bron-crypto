package przs

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Seeds ds.Map[sharing.ID, [32]byte]
