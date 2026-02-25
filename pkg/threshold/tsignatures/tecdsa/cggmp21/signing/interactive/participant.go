package interactive_signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21"
	"github.com/cronokirby/saferith"
	"io"
)

var (
	_ types.ThresholdSignatureParticipant = (*Cosigner)(nil)
)

type Cosigner struct {
	MyIdentityKey    types.AuthKey
	MySharingId      types.SharingID
	MyShard          *cggmp21.Shard
	SharingCfg       types.SharingConfig
	Protocol         types.ThresholdSignatureProtocol
	TheQuorum        ds.Set[types.IdentityKey]
	QuorumIdentities map[types.SharingID]types.IdentityKey
	Prng             io.Reader
	state            State
}

type State struct {
	k           curves.Scalar
	bigK        map[types.SharingID]*paillier.CipherText
	bigG        map[types.SharingID]*paillier.CipherText
	betaSum     *saferith.Int
	betaDashSum *saferith.Int
	gamma       curves.Scalar
	bigGamma    curves.Point
	delta       curves.Scalar
	bigDelta    curves.Point
	chi         curves.Scalar
	bigS        curves.Point
}

func NewCosigner(myAuthKey types.AuthKey, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], myShard *cggmp21.Shard, prng io.Reader) (*Cosigner, error) {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myAuthKey)
	quorumIdentities := make(map[types.SharingID]types.IdentityKey)
	for identityKey := range quorum.Iter() {
		sharingId, _ := sharingCfg.Reverse().Get(identityKey)
		quorumIdentities[sharingId] = identityKey
	}

	return &Cosigner{
		MyIdentityKey:    myAuthKey,
		MySharingId:      mySharingId,
		MyShard:          myShard,
		SharingCfg:       sharingCfg,
		Protocol:         protocol,
		TheQuorum:        quorum,
		QuorumIdentities: quorumIdentities,
		Prng:             prng,
	}, nil
}

func (c *Cosigner) IdentityKey() types.IdentityKey {
	return c.MyIdentityKey
}

func (c *Cosigner) SharingId() types.SharingID {
	return c.MySharingId
}

func (c *Cosigner) Quorum() ds.Set[types.IdentityKey] {
	return c.TheQuorum
}
