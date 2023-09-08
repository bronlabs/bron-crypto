package tecdsa

import (
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
)

type Shard struct {
	Main   *dkls23.Shard
	Backup *lindell17.Shard

	_ helper_types.Incomparable
}

func (s *Shard) SigningKeyShare() *dkls23.SigningKeyShare {
	return s.Main.SigningKeyShare
}
