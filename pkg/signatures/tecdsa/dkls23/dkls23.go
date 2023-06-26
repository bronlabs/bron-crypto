package dkls23

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures"
)

type Participant interface {
	integration.Participant
	IsSignatureAggregator() bool
}

type SigningKeyShare = signatures.SigningKeyShare
type PublicKeyShares = signatures.PublicKeyShares
