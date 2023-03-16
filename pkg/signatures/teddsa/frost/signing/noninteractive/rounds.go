package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
)

func (nic *NonInteractiveCosigner) Sign(preSignatureIndex int, message []byte) (*frost.PartialSignature, error) {
	return nil, errors.New("not implemented")
}

func (nic *NonInteractiveCosigner) Aggregate(partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	return nil, errors.New("not implemented")
}
