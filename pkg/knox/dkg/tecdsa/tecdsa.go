package tecdsa

import (
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
)

type Shard struct {
	Main   *dkls23.Shard
	Backup *lindell17.Shard

	_ helper_types.Incomparable
}

func (s *Shard) SigningKeyShare() *dkls23.SigningKeyShare {
	return s.Main.SigningKeyShare
}
