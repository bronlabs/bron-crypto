package tecdsa

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
)

type Shard struct {
	Main   *dkls24.Shard
	Backup *lindell17.Shard

	_ types.Incomparable
}

func (s *Shard) SigningKeyShare() *dkls24.SigningKeyShare {
	return s.Main.SigningKeyShare
}
