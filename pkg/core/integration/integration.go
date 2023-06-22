package integration

import (
	"encoding/binary"
	"encoding/json"
	"hash"
	"sort"

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

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point
}

func (s *SigningKeyShare) Validate() error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if s.PublicKey.IsIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	if !s.PublicKey.IsOnCurve() {
		return errs.NewNotOnCurve("public key is not on curve")
	}

	if s.PublicKey.CurveName() == curves.ED25519Name {
		edwardsPoint, ok := s.PublicKey.(*curves.PointEd25519)
		if !ok {
			return errs.NewDeserializationFailed("curve is ed25519 but the public key could not be type casted to the correct point struct")
		}
		// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptibe
		// to a key substitution attack (specifically, it won't have message bound security). Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
		if edwardsPoint.IsSmallOrder() {
			return errs.NewFailed("public key is small order")
		}
	}
	return nil
}

type PublicKeyShares struct {
	Curve     *curves.Curve
	PublicKey curves.Point
	SharesMap map[IdentityKey]curves.Point
}

// TODO: write down validation (lambda trick)
// func (p *PublicKeyShares) Validate() error {
// 	derivedPublicKey := p.Curve.Point.Identity()
// 	for _, share := range p.SharesMap {
// 		derivedPublicKey = derivedPublicKey.Add(share)
// 	}
// 	if !derivedPublicKey.Equal(p.PublicKey) {
// 		return errors.New("public key shares can't be combined to the entire public key")
// 	}
// 	return nil
// }

type CohortConfig struct {
	CipherSuite  *CipherSuite
	Protocol     protocol.Protocol
	Threshold    int
	TotalParties int
	Participants []IdentityKey

	SignatureAggregators []IdentityKey
	PreSignatureComposer IdentityKey

	participantHashSet map[IdentityKey]bool
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

	c.participantHashSet = map[IdentityKey]bool{}
	for _, identityKey := range c.Participants {
		if c.participantHashSet[identityKey] {
			return errs.NewDuplicate("found duplicate identity key")
		}
		c.participantHashSet[identityKey] = true
	}

	if c.SignatureAggregators == nil || len(c.SignatureAggregators) == 0 {
		return errs.NewIsNil("need to specify at least one signature aggregator")
	}

	return nil
}

func (c *CohortConfig) IsInCohort(identityKey IdentityKey) bool {
	c.cacheParticipantHashSet()
	return c.participantHashSet[identityKey]
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

func (c *CohortConfig) cacheParticipantHashSet() {
	if c.participantHashSet == nil || len(c.participantHashSet) == 0 {
		c.participantHashSet = map[IdentityKey]bool{}
		for _, identityKey := range c.Participants {
			c.participantHashSet[identityKey] = true
		}
	}
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

func DeriveShamirIds(myIdentityKey IdentityKey, identityKeys []IdentityKey) (idToKey map[int]IdentityKey, keyToId map[IdentityKey]int, myShamirId int) {
	idToKey = make(map[int]IdentityKey)
	keyToId = make(map[IdentityKey]int)
	myShamirId = -1

	for shamirIdMinusOne, identityKey := range identityKeys {
		shamirId := shamirIdMinusOne + 1
		idToKey[shamirId] = identityKey
		keyToId[identityKey] = shamirId
		if myIdentityKey != nil && identityKey.PublicKey().Equal(myIdentityKey.PublicKey()) {
			myShamirId = shamirId
		}
	}

	return idToKey, keyToId, myShamirId
}
