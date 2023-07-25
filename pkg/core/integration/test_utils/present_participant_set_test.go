package test_utils

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
	"testing"
)

func TestCheckNilParticipant(t *testing.T) {
	_, err := integration.NewPresentParticipantSet([]integration.IdentityKey{nil})
	assert.True(t, errs.IsIsNil(err))
}

func TestCheckDuplicateParticipantByPubkey(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	_, err = integration.NewPresentParticipantSet([]integration.IdentityKey{identityAlice, identityBob})
	assert.True(t, errs.IsDuplicate(err))
}

func TestCheckExistIdentity(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{2}), nil)
	set, err := integration.NewPresentParticipantSet([]integration.IdentityKey{identityAlice})
	assert.NoError(t, err)
	assert.True(t, set.Size() == 1)
	assert.True(t, set.Exist(identityAlice))
	assert.False(t, set.Exist(identityBob))
}
