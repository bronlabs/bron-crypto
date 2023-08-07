package frost

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type (
	SigningKeyShare = threshold.SigningKeyShare
	PublicKeyShares = threshold.PublicKeyShares
)

// TODO: Refactor and use this.
type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
}

type PartialSignature struct {
	Zi curves.Scalar
}
