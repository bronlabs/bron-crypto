package dkg

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
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
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
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

func (p *Participant) Run(router roundbased.MessageRouter) (*frost.Shard, error) {
	id := p.IdentityKey()
	r1b := roundbased.NewBroadcastRound[*Round1Broadcast](id, 1, router)
	r1u := roundbased.NewUnicastRound[*Round1P2P](id, 1, router)

	// round 1
	r1bo, r1uo, err := p.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1b.BroadcastOut() <- r1bo
	r1u.UnicastOut() <- r1uo

	// round 2
	r2Out, err := p.Round2(<-r1b.BroadcastIn(), <-r1u.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 2 failed")
	}
	return r2Out, nil
}
