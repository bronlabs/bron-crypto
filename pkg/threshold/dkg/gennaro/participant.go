package gennaro

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	pedersen_comm "github.com/bronlabs/krypton-primitives/pkg/commitments/pedersen"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	pedersen_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/pedersen"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"io"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MySharingId types.SharingID
	MyAuthKey   types.AuthKey
	Protocol    types.ThresholdProtocol
	SharingCfg  types.SharingConfig
	Tape        transcripts.Transcript
	Prng        io.Reader
	Round       int
	State       *State
}

type State struct {
	ck                     *pedersen_comm.CommittingKey
	polynomialCoefficients []curves.Scalar

	pedersenVss           *pedersen_vss.Scheme
	pedersenVerifications map[types.SharingID][]pedersen_comm.Commitment
	pedersenShares        map[types.SharingID]*pedersen_vss.Share

	feldmanVss           *feldman_vss.Scheme
	feldmanVerifications map[types.SharingID][]curves.Point
}

func NewParticipant(sessionId []byte, myAuthKey types.AuthKey, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader) (*Participant, error) {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myAuthKey)

	tape.AppendMessages("sessionId", sessionId)
	hBytes, err := tape.ExtractBytes("pedersenKey", 64)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract bytes from transcript")
	}
	h, err := protocol.Curve().Hash(hBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash to curve")
	}
	ck := pedersen_comm.NewCommittingKey(protocol.Curve().Generator(), h)

	pedersenVss := pedersen_vss.NewScheme(ck, protocol.Threshold(), protocol.TotalParties())
	feldmanVss, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create feldman-VSS scheme")
	}

	p := &Participant{
		MySharingId: mySharingId,
		MyAuthKey:   myAuthKey,
		Protocol:    protocol,
		SharingCfg:  sharingCfg,
		Tape:        tape,
		Prng:        prng,
		Round:       1,
		State: &State{
			ck:          ck,
			pedersenVss: pedersenVss,
			feldmanVss:  feldmanVss,
		},
	}

	return p, nil
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}
