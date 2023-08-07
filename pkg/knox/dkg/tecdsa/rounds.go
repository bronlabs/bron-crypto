package tecdsa

import (
	"github.com/copperexchange/knox-primitives/pkg/agreeonrandom"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	dkls23 "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/keygen/dkg"
	lindell17 "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg"
)

type Round1Broadcast = agreeonrandom.Round1Broadcast

type (
	Round2Broadcast = dkls23.Round1Broadcast
	Round2P2P       = dkls23.Round1P2P
)

type (
	Round3Broadcast = dkls23.Round2Broadcast
	Round3P2P       = dkls23.Round2P2P
)

type (
	Round4P2P       = dkls23.Round3P2P
	Round4Broadcast = lindell17.Round1Broadcast
)

type (
	Round5P2P       = dkls23.Round4P2P
	Round5Broadcast = lindell17.Round2Broadcast
)

type (
	Round6P2P       = dkls23.Round5P2P
	Round6Broadcast = lindell17.Round3Broadcast
)

type Round7P2P = lindell17.Round4P2P

type Round8P2P = lindell17.Round5P2P

type Round9P2P = lindell17.Round6P2P

type Round10P2P = lindell17.Round7P2P

func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	outputBroadcast, err := p.SIDParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce session id")
	}
	p.round++
	return outputBroadcast, nil
}

func (p *Participant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	var err error
	p.UniqueSessionId, err = p.SIDParty.Round2(round1output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce session id")
	}
	p.Main, err = dkls23.NewParticipant(p.UniqueSessionId, p.GetIdentityKey(), p.GetCohortConfig(), p.prng, p.transcript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct main party")
	}
	outputBroadcast, outputP2P, err := p.Main.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce main shard")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round3(round2broadcast map[integration.IdentityKey]*Round2Broadcast, round2p2p map[integration.IdentityKey]*Round2P2P) (*Round3Broadcast, map[integration.IdentityKey]*Round3P2P, error) {
	if p.round != 3 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	outputBroadcast, outputP2P, err := p.Main.Round2(round2broadcast, round2p2p)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce main shard")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round4(round3broadcast map[integration.IdentityKey]*Round3Broadcast, round3p2p map[integration.IdentityKey]*Round3P2P) (*Round4Broadcast, map[integration.IdentityKey]Round4P2P, error) {
	if p.round != 4 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 4", p.round)
	}
	outputP2P, err := p.Main.Round3(round3broadcast, round3p2p)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce main shard")
	}
	p.Backup, err = lindell17.NewBackupParticipant(p.GetIdentityKey(), p.Main.Shard.SigningKeyShare, p.Main.Shard.PublicKeyShares, p.GetCohortConfig(), p.prng, p.UniqueSessionId, p.transcript)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce backup party")
	}
	outputBroadcast, err := p.Backup.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce backup material")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round5(round4broadcast map[integration.IdentityKey]*Round4Broadcast, round4p2p map[integration.IdentityKey]Round4P2P) (*Round5Broadcast, map[integration.IdentityKey]Round5P2P, error) {
	if p.round != 5 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 5", p.round)
	}
	outputP2P, err := p.Main.Round4(round4p2p)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce main shard")
	}
	outputBroadcast, err := p.Backup.Round2(round4broadcast)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round6(round5broadcast map[integration.IdentityKey]*Round5Broadcast, round5p2p map[integration.IdentityKey]Round5P2P) (*Round6Broadcast, map[integration.IdentityKey]Round6P2P, error) {
	if p.round != 6 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 6", p.round)
	}
	outputP2P, err := p.Main.Round5(round5p2p)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce main shard")
	}
	outputBroadcast, err := p.Backup.Round3(round5broadcast)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round7(round6broadcast map[integration.IdentityKey]*Round6Broadcast, round6p2p map[integration.IdentityKey]Round6P2P) (map[integration.IdentityKey]*Round7P2P, error) {
	if p.round != 7 {
		return nil, errs.NewInvalidRound("round mismatch %d != 7", p.round)
	}
	var err error
	p.Shard.Main, err = p.Main.Round6(round6p2p)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce main shard")
	}
	outputP2P, err := p.Backup.Round4(round6broadcast)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	p.round++
	return outputP2P, nil
}

func (p *Participant) Round8(input map[integration.IdentityKey]*Round7P2P) (map[integration.IdentityKey]*Round8P2P, error) {
	if p.round != 8 {
		return nil, errs.NewInvalidRound("round mismatch %d != 8", p.round)
	}
	outputP2P, err := p.Backup.Round5(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	p.round++
	return outputP2P, nil
}

func (p *Participant) Round9(input map[integration.IdentityKey]*Round8P2P) (map[integration.IdentityKey]*Round9P2P, error) {
	if p.round != 9 {
		return nil, errs.NewInvalidRound("round mismatch %d != 9", p.round)
	}
	outputP2P, err := p.Backup.Round6(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	p.round++
	return outputP2P, nil
}

func (p *Participant) Round10(input map[integration.IdentityKey]*Round9P2P) (map[integration.IdentityKey]*Round10P2P, error) {
	if p.round != 10 {
		return nil, errs.NewInvalidRound("round mismatch %d != 10", p.round)
	}
	outputP2P, err := p.Backup.Round7(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	p.round++
	return outputP2P, nil
}

func (p *Participant) Round11(input map[integration.IdentityKey]*Round10P2P) (*Shard, error) {
	if p.round != 11 {
		return nil, errs.NewInvalidRound("round mismatch %d != 11", p.round)
	}
	var err error
	p.Shard.Backup, err = p.Backup.Round8(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce backup shard")
	}
	if err := p.Shard.SigningKeyShare().Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "signing key share is invalid. something is seriously wrong")
	}
	p.round++
	return p.Shard, nil
}
