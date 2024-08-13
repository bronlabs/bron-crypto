package signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	mult "github.com/copperexchange/krypton-primitives/pkg/threshold/mult/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ types.ThresholdSignatureParticipant = (*Participant)(nil)

type Participant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	shard *dkls23.Shard
}

func NewParticipant(
	myAuthKey types.AuthKey,
	prng io.Reader,
	protocol types.ThresholdSignatureProtocol,
	sessionId []byte,
	transcript transcripts.Transcript,
	mySharingId types.SharingID,
	sharingConfig types.SharingConfig,
	shard *dkls23.Shard,
) *Participant {
	return &Participant{
		myAuthKey:     myAuthKey,
		Prng:          prng,
		Protocol:      protocol,
		Round:         1,
		SessionId:     sessionId,
		Transcript:    transcript,
		mySharingId:   mySharingId,
		sharingConfig: sharingConfig,
		shard:         shard,
	}
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Participant) Shard() *dkls23.Shard {
	return p.shard
}

func (p *Participant) SharingConfig() types.SharingConfig {
	return p.sharingConfig
}

func (p *Participant) IsSignatureAggregator() bool {
	return p.Protocol.Participants().Contains(p.IdentityKey())
}

// Multiplication contains corresponding participant objects for pairwise multiplication subProtocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob

	_ ds.Incomparable
}

type SubProtocols struct {
	// use to get the secret key mask (zeta_i)
	ZeroShareSampling *sample.Participant
	// pairwise multiplication protocol i.e. each party acts as alice and bob against every party
	Multiplication ds.Map[types.IdentityKey, *Multiplication]

	_ ds.Incomparable
}

type SignerState struct {
	Phi_i                          curves.Scalar
	Sk_i                           curves.Scalar
	R_i                            curves.Scalar
	Zeta_i                         curves.Scalar
	BigR_i                         curves.Point
	Pk_i                           curves.Point
	Cu_i                           map[types.SharingID]curves.Scalar
	Cv_i                           map[types.SharingID]curves.Scalar
	Du_i                           map[types.SharingID]curves.Scalar
	Dv_i                           map[types.SharingID]curves.Scalar
	Psi_i                          map[types.SharingID]curves.Scalar
	Chi_i                          map[types.SharingID]curves.Scalar
	InstanceKeyOpening             map[types.SharingID]hashcommitments.Witness
	ReceivedInstanceKeyCommitments map[types.SharingID]hashcommitments.Commitment
	ReceivedBigR_i                 ds.Map[types.IdentityKey, curves.Point]
	Protocols                      *SubProtocols

	_ ds.Incomparable
}
