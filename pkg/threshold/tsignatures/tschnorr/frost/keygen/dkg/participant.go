package dkg

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
)

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	pedersenParty *pedersen.Participant

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.pedersenParty.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.pedersenParty.SharingId()
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, prng io.Reader) (*Participant, error) {
	if err := validateInputs(protocol, authKey, prng); err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}
	pedersenParty, err := pedersen.NewParticipant(sessionId, authKey, protocol, fiatShamir.Name, nil, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct frost dkg participant out of pedersen dkg participant")
	}
	participant := &Participant{
		pedersenParty: pedersenParty,
	}
	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct frost dkg participant")
	}
	return participant, nil
}

func validateInputs(protocol types.ThresholdProtocol, authKey types.AuthKey, prng io.Reader) error {
	if err := types.ValidateThresholdProtocol(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
