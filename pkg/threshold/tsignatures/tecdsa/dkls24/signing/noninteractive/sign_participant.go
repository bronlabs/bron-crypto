package noninteractiveSigning

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

type Cosigner struct {
	myAuthKey             integration.AuthKey
	mySharingId           int
	myShard               *dkls24.Shard
	cohortConfig          *integration.CohortConfig
	sessionParticipants   *hashset.HashSet[integration.IdentityKey]
	identityKeyToShamirId map[types.IdentityHash]int
	preSignature          *dkls24.PreSignature
}

var _ signing.Participant = (*Cosigner)(nil)

func (c *Cosigner) GetShard() *dkls24.Shard {
	return c.myShard
}

func (c *Cosigner) GetIdentityHashToSharingId() map[types.IdentityHash]int {
	return c.identityKeyToShamirId
}

func (*Cosigner) GetPrng() io.Reader {
	return nil
}

func (*Cosigner) GetSessionId() []byte {
	return nil
}

func (c *Cosigner) GetAuthKey() integration.AuthKey {
	return c.myAuthKey
}

func (c *Cosigner) GetSharingId() int {
	return c.mySharingId
}

func (c *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return c.cohortConfig
}

func (c *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range c.cohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(c.myAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

var _ dkls24.Participant = (*Cosigner)(nil)

func NewCosigner(myAuthKey integration.AuthKey, myShard *dkls24.Shard, cohortConfig *integration.CohortConfig, sessionParticipants *hashset.HashSet[integration.IdentityKey], preSignature *dkls24.PreSignature) (cosigner *Cosigner, err error) {
	_, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)

	return &Cosigner{
		myAuthKey:             myAuthKey,
		mySharingId:           myShamirId,
		myShard:               myShard,
		cohortConfig:          cohortConfig,
		sessionParticipants:   sessionParticipants,
		identityKeyToShamirId: identityKeyToShamirId,
		preSignature:          preSignature,
	}, nil
}
