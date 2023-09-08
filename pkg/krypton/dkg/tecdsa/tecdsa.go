package tecdsa

import (
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/lindell17"
)

type Shard struct {
	Main   *dkls23.Shard
	Backup *lindell17.Shard

	_ types.Incomparable
}

func (s *Shard) SigningKeyShare() *dkls23.SigningKeyShare {
	return s.Main.SigningKeyShare
}
