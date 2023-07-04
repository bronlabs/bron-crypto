package frost

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type SigningKeyShare = threshold.SigningKeyShare
type PublicKeyShares = threshold.PublicKeyShares

// TODO: Refactor and use this
type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
}

type PartialSignature struct {
	Zi curves.Scalar
}
