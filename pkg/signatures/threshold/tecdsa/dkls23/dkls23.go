package dkls23

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type SigningKeyShare = threshold.SigningKeyShare
type PublicKeyShares = threshold.PublicKeyShares
type PairwiseSeeds = zero.PairwiseSeeds

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
	PairwiseSeeds   PairwiseSeeds
}
