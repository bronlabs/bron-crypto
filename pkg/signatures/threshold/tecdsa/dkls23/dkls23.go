package dkls23

import (
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type (
	SigningKeyShare = threshold.SigningKeyShare
	PublicKeyShares = threshold.PublicKeyShares
	PairwiseSeeds   = zero.PairwiseSeeds
)

type BaseOTConfig struct {
	AsSender   *vsot.SenderOutput
	AsReceiver *vsot.ReceiverOutput
}

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
	PairwiseSeeds   PairwiseSeeds
	PairwiseBaseOTs *hashmap.HashMap[integration.IdentityKey, *BaseOTConfig]
}
