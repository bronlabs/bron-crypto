package gennaro

import (
	"encoding/hex"
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	feldman_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	pedersen_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"io"
)

//var (
//	_ types.ThresholdParticipant = (*Participant)(nil)
//)

type Participant[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	MySharingId types.SharingID
	MyAuthKey   types.AuthKey
	Protocol    types.ThresholdProtocol[C, P, F, S]
	SharingCfg  types.SharingConfig
	Tape        transcripts.Transcript
	Prng        io.Reader
	Round       int
	State       *State[C, P, F, S]
}

type State[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	ck                     *pedersen_comm.CommittingKey[P, F, S]
	polynomialCoefficients []S

	pedersenVss           *pedersen_vss.Scheme[C, P, F, S]
	pedersenVerifications map[types.SharingID][]*pedersen_comm.Commitment[P, F, S]
	pedersenShares        map[types.SharingID]*pedersen_vss.Share[S]

	feldmanVss           *feldman_vss.Scheme[C, P, F, S]
	feldmanVerifications map[types.SharingID][]P
}

func NewParticipant[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](sessionId []byte, myAuthKey types.AuthKey, protocol types.ThresholdProtocol[C, P, F, S], tape transcripts.Transcript, prng io.Reader) (*Participant[C, P, F, S], error) {
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, _ := sharingCfg.Reverse().Get(myAuthKey)

	tape.AppendDomainSeparator(fmt.Sprintf("GennaroDKG-%s", hex.EncodeToString(sessionId)))
	hBytes, err := tape.ExtractBytes("pedersenKey", 64)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract bytes from transcript")
	}
	h, err := protocol.Curve().Hash(hBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot hash to curve")
	}
	ck := pedersen_comm.NewCommittingKey(protocol.Curve().Generator(), h)

	pedersenVss, err := pedersen_vss.NewScheme(protocol.Curve(), ck, protocol.Threshold(), protocol.TotalParties())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Pedersen-VSS scheme")
	}
	feldmanVss, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Feldman-VSS scheme")
	}

	p := &Participant[C, P, F, S]{
		MySharingId: mySharingId,
		MyAuthKey:   myAuthKey,
		Protocol:    protocol,
		SharingCfg:  sharingCfg,
		Tape:        tape,
		Prng:        prng,
		Round:       1,
		State: &State[C, P, F, S]{
			ck:          ck,
			pedersenVss: pedersenVss,
			feldmanVss:  feldmanVss,
		},
	}

	return p, nil
}

func (p *Participant[C, P, F, S]) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant[C, P, F, S]) SharingId() types.SharingID {
	return p.MySharingId
}
