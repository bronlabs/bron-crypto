package integration

import (
	"encoding/binary"
	"encoding/json"
	"hash"
	"sort"

	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/hashmap"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
)

type Participant interface {
	GetIdentityKey() IdentityKey
	GetShamirId() int
	GetCohortConfig() *CohortConfig
}

type IdentityKey interface {
	Sign(message []byte) []byte
	Verify(signature []byte, publicKey curves.Point, message []byte) error
	PublicKey() curves.Point
	HashCode() [32]byte
}

type CipherSuite struct {
	Curve *curves.Curve
	Hash  func() hash.Hash
}

func (cs *CipherSuite) Validate() error {
	if cs == nil {
		return errs.NewIsNil("ciphersuite is nil")
	}
	if cs.Curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	if cs.Hash == nil {
		return errs.NewIsNil("hash is nil")
	}
	return nil
}

type CohortConfig struct {
	CipherSuite  *CipherSuite
	Protocol     protocol.Protocol
	Threshold    int
	TotalParties int
	Participants []IdentityKey

	SignatureAggregators []IdentityKey
	PreSignatureComposer IdentityKey

	participantHashSet hashmap.HashMap[IdentityKey]
}

func (c *CohortConfig) Validate() error {
	if c == nil {
		return errs.NewIsNil("cohort config is nil")
	}

	if err := c.CipherSuite.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "ciphersuite is invalid")
	}

	if supported := protocol.Supported[c.Protocol]; !supported {
		return errs.NewInvalidArgument("protocol %s is not supported", c.Protocol)
	}

	if c.Threshold <= 0 {
		return errs.NewIncorrectCount("threshold is nonpositive")
	}
	if c.Threshold > c.TotalParties {
		return errs.NewIncorrectCount("threshold is greater that total parties")
	}
	if c.TotalParties != len(c.Participants) {
		return errs.NewIncorrectCount("number of provided participants is not equal to total parties")
	}
	for i, participant := range c.Participants {
		if participant == nil {
			return errs.NewIsNil("participant %d is nil", i)
		}
	}
	participantHashSet, err := hashmap.NewHashmap(c.Participants)
	if err != nil {
		return err
	}
	c.participantHashSet = participantHashSet

	if c.SignatureAggregators == nil || len(c.SignatureAggregators) == 0 {
		return errs.NewIsNil("need to specify at least one signature aggregator")
	}

	return nil
}

func (c *CohortConfig) IsInCohort(identityKey IdentityKey) bool {
	_, found := hashmap.Get(c.participantHashSet, identityKey)
	return found
}

func (c *CohortConfig) IsSignatureAggregator(identityKey IdentityKey) bool {
	for _, aggregator := range c.SignatureAggregators {
		if aggregator.PublicKey().Equal(identityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func (c *CohortConfig) UnmarshalJSON(data []byte) error {
	var result CohortConfig
	if err := json.Unmarshal(data, &result); err != nil {
		return errs.WrapDeserializationFailed(err, "failed to unmarshal json")
	}
	if err := result.Validate(); err != nil {
		return errs.WrapDeserializationFailed(err, "cohort config is invalid")
	}
	*c = result
	return nil

}

func SortIdentityKeys(identityKeys []IdentityKey) []IdentityKey {
	copied := append([]IdentityKey{}, identityKeys...)
	sort.Slice(copied, func(i, j int) bool {
		switch copied[i].PublicKey().CurveName() {
		case curves.ED25519Name:
			iKey := binary.LittleEndian.Uint64(copied[i].PublicKey().ToAffineCompressed())
			jKey := binary.LittleEndian.Uint64(copied[j].PublicKey().ToAffineCompressed())
			return iKey < jKey
		default:
			iKey := binary.BigEndian.Uint64(copied[i].PublicKey().ToAffineCompressed())
			jKey := binary.BigEndian.Uint64(copied[j].PublicKey().ToAffineCompressed())
			return iKey < jKey
		}
	})
	return copied
}

func DeriveSharingIds(myIdentityKey IdentityKey, identityKeys []IdentityKey) (idToKey map[int]IdentityKey, keyToId map[IdentityKey]int, mySharingId int) {
	identityKeys = SortIdentityKeys(identityKeys)
	idToKey = make(map[int]IdentityKey)
	keyToId = make(map[IdentityKey]int)
	mySharingId = -1

	for sharingIdMinusOne, identityKey := range identityKeys {
		sharingId := sharingIdMinusOne + 1
		idToKey[sharingId] = identityKey
		keyToId[identityKey] = sharingId
		if myIdentityKey != nil && identityKey.PublicKey().Equal(myIdentityKey.PublicKey()) {
			mySharingId = sharingId
		}
	}

	return idToKey, keyToId, mySharingId
}
