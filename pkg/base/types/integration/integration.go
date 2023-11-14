package integration

import (
	"encoding/binary"
	"encoding/json"
	"hash"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Participant interface {
	GetIdentityKey() IdentityKey
	GetSharingId() int
	GetCohortConfig() *CohortConfig
}

type IdentityKey interface {
	Sign(message []byte) []byte
	Verify(signature []byte, publicKey curves.Point, message []byte) error
	PublicKey() curves.Point
	PrivateKey() curves.Scalar
	types.Hashable
}

type CipherSuite struct {
	Curve curves.Curve
	Hash  func() hash.Hash

	_ types.Incomparable
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
	Participants *hashset.HashSet[IdentityKey]
	Protocol     *ProtocolConfig

	_ types.Incomparable
}

type ProtocolConfig struct {
	Name         protocols.Protocol
	Threshold    int
	TotalParties int

	SignatureAggregators *hashset.HashSet[IdentityKey]

	_ types.Incomparable
}

func (c *CohortConfig) Validate() error {
	if c == nil {
		return errs.NewIsNil("cohort config is nil")
	}

	if err := c.CipherSuite.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "ciphersuite is invalid")
	}

	for i, participant := range c.Participants.Iter() {
		if participant == nil {
			return errs.NewIsNil("participant %x is nil", i)
		}
	}
	if c.Protocol != nil {
		if c.Protocol.TotalParties != c.Participants.Len() {
			return errs.NewIncorrectCount("number of provided participants is not equal to total parties")
		}
		return c.Protocol.Validate()
	}
	return nil
}

func (c *ProtocolConfig) Validate() error {
	if c == nil {
		return errs.NewIsNil("protocol config is nil")
	}
	if supported := protocols.Supported[c.Name]; !supported {
		return errs.NewInvalidArgument("protocol %s is not supported", c.Name)
	}
	if c.Threshold <= 0 {
		return errs.NewIncorrectCount("threshold is nonpositive")
	}
	if c.Threshold > c.TotalParties {
		return errs.NewIncorrectCount("threshold is greater that total parties")
	}

	if c.SignatureAggregators == nil || c.SignatureAggregators.Len() == 0 {
		return errs.NewIsNil("need to specify at least one signature aggregator")
	}
	return nil
}

func (c *CohortConfig) IsInCohort(identityKey IdentityKey) bool {
	_, found := c.Participants.Get(identityKey)
	return found
}

func (c *CohortConfig) IsSignatureAggregator(identityKey IdentityKey) bool {
	if c.Protocol == nil {
		return false
	}
	for _, aggregator := range c.Protocol.SignatureAggregators.Iter() {
		if aggregator.PublicKey().Equal(identityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func (c *CohortConfig) UnmarshalJSON(data []byte) error {
	var result CohortConfig
	if err := json.Unmarshal(data, &result); err != nil {
		return errs.WrapSerializationError(err, "failed to unmarshal json")
	}
	if err := result.Validate(); err != nil {
		return errs.WrapSerializationError(err, "cohort config is invalid")
	}
	*c = result
	return nil
}

func DeriveSharingIds(myIdentityKey IdentityKey, identityKeys *hashset.HashSet[IdentityKey]) (idToKey map[int]IdentityKey, keyToId map[types.IdentityHash]int, mySharingId int) {
	sortedIdentityKeys := ByPublicKey(identityKeys.List())
	sort.Sort(sortedIdentityKeys)
	idToKey = make(map[int]IdentityKey)
	keyToId = make(map[types.IdentityHash]int)
	mySharingId = -1

	for sharingIdMinusOne, identityKey := range sortedIdentityKeys {
		sharingId := sharingIdMinusOne + 1
		idToKey[sharingId] = identityKey
		keyToId[identityKey.Hash()] = sharingId
		if myIdentityKey != nil && types.Equals(identityKey, myIdentityKey) {
			mySharingId = sharingId
		}
	}

	return idToKey, keyToId, mySharingId
}

type ByPublicKey []IdentityKey

func (l ByPublicKey) Len() int {
	return len(l)
}

func (l ByPublicKey) Less(i, j int) bool {
	switch l[i].PublicKey().CurveName() {
	case edwards25519.Name:
		iKey := binary.LittleEndian.Uint64(l[i].PublicKey().ToAffineCompressed())
		jKey := binary.LittleEndian.Uint64(l[j].PublicKey().ToAffineCompressed())
		return iKey < jKey
	default:
		iKey := binary.BigEndian.Uint64(l[i].PublicKey().ToAffineCompressed())
		jKey := binary.BigEndian.Uint64(l[j].PublicKey().ToAffineCompressed())
		return iKey < jKey
	}
}

func (l ByPublicKey) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}
