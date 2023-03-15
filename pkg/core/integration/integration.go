package integration

import (
	"encoding/base64"
	"encoding/json"
	"hash"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/pkg/errors"
)

type IdentityKey interface {
	Sign(message []byte) []byte
	PublicKey() curves.Point
}

type CipherSuite struct {
	Curve *curves.Curve
	Hash  func() hash.Hash
}

func (cs *CipherSuite) Validate() error {
	if cs == nil {
		return errors.New("ciphersuite is nil")
	}
	if cs.Curve == nil {
		return errors.New("curve is nil")
	}
	if cs.Hash == nil {
		return errors.New("hash is nil")
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
}

func (c *CohortConfig) Validate() error {
	if c == nil {
		return errors.New("cohort config is nil")
	}

	if err := c.CipherSuite.Validate(); err != nil {
		return errors.Wrap(err, "ciphersuite is invalid")
	}

	if supported := protocol.Supported[c.Protocol]; !supported {
		return errors.Errorf("protocol %s is not supported", c.Protocol)
	}

	if c.Threshold <= 0 {
		return errors.New("threshold is nonpositive")
	}
	if c.Threshold > c.TotalParties {
		return errors.New("threshold is greater that total parties")
	}
	if c.TotalParties != len(c.Participants) {
		return errors.New("number of provided participants is not equal to total parties")
	}

	participantHashSet := map[string]bool{}
	for _, identityKey := range c.Participants {
		serializedIdentityKey, err := SerializePublicKey(identityKey.PublicKey())
		if err != nil {
			return errors.Wrap(err, "identity key is not serializable")
		}
		if participantHashSet[serializedIdentityKey] {
			return errors.New("found duplicate identity key")
		}
		participantHashSet[serializedIdentityKey] = true
	}

	if c.SignatureAggregators == nil || len(c.SignatureAggregators) == 0 {
		return errors.New("need to specify at least one signature aggregator")
	}

	return nil
}

func (c *CohortConfig) UnmarshalJSON(data []byte) error {
	var result CohortConfig
	if err := json.Unmarshal(data, &result); err != nil {
		return errors.Wrap(err, "failed to unmarshal json")
	}
	if err := result.Validate(); err != nil {
		return errors.Wrap(err, "cohort config is invalid")
	}
	*c = result
	return nil

}

func SerializePublicKey(publicKey curves.Point) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(publicKey.ToAffineCompressed())
	return encoded, nil
}
