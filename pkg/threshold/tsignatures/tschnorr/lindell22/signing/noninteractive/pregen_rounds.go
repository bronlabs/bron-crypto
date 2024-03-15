package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	commitmentDomainRLabel = "Lindell2022PreGenR-"
	transcriptDLogSLabel   = "Lindell2022PreGenDLogS-"
)

func (p *PreGenParticipant) Round1() (broadcastOutput *Round1Broadcast, unicastOutput network.RoundMessages[*Round1P2P], err error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}

	// 1. choose a random k1 & k2
	k1, err := p.Protocol().Curve().ScalarField().Random(p.Prng())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random k")
	}
	k2, err := p.Protocol().Curve().ScalarField().Random(p.Prng())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random k2")
	}

	// 2. compute R1 = k1 * G, R2 = k2 * G
	bigR1 := p.Protocol().Curve().ScalarBaseMult(k1)
	bigR2 := p.Protocol().Curve().ScalarBaseMult(k2)

	// 3. compute Rcom = commit(R1, R2, pid, sessionId, S)
	bigRCommitment, bigRWitness, err := commitments.Commit(p.SessionId(), p.Prng(), []byte(commitmentDomainRLabel), bigR1.ToAffineCompressed(), bigR2.ToAffineCompressed(), p.state.pid, p.state.bigS)
	if err != nil {
		return nil, nil, errs.NewFailed("cannot commit to R")
	}

	unicast, err := p.przsSetupParticipant.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "PRZS round 1 failed")
	}

	broadcast := &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}

	p.state.k1 = k1
	p.state.k2 = k2
	p.state.bigR1 = bigR1
	p.state.bigR2 = bigR2
	p.state.bigRWitness = bigRWitness
	p.NextRound()

	return broadcast, unicast, nil
}

func (p *PreGenParticipant) Round2(broadcastInput network.RoundMessages[*Round1Broadcast], unicastInput network.RoundMessages[*Round1P2P]) (broadcastOutput *Round2Broadcast, unicastOutput network.RoundMessages[*Round2P2P], err error) {
	// Validation, unicastInput is delegated to przs.Round2A
	if err := p.InRound(2); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessages(p.preSigners, p.IdentityKey(), broadcastInput); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 1 broadcast input")
	}

	theirBigRCommitment := hashmap.NewHashableHashMap[types.IdentityKey, commitments.Commitment]()
	for identity := range p.preSigners.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		inBroadcast, _ := broadcastInput.Get(identity)
		theirBigRCommitment.Put(identity, inBroadcast.BigRCommitment)
	}

	// 1. compute proof of dlog knowledge of R1 & R2
	bigR1Proof, err := dlogProve(p.state.k1, p.state.bigR1, p.SessionId(), p.state.bigS, p.nic, p.Transcript().Clone(), p.Prng())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
	}
	bigR2Proof, err := dlogProve(p.state.k2, p.state.bigR2, p.SessionId(), p.state.bigS, p.nic, p.Transcript().Clone(), p.Prng())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	unicast, err := p.przsSetupParticipant.Round2(unicastInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "PRZS round 2 failed")
	}

	broadcast := &Round2Broadcast{
		BigR1:       p.state.bigR1,
		BigR2:       p.state.bigR2,
		BigRWitness: p.state.bigRWitness,
		BigR1Proof:  bigR1Proof,
		BigR2Proof:  bigR2Proof,
	}
	p.state.theirBigRCommitment = theirBigRCommitment
	p.NextRound()

	// 2. broadcast proof and opening of R1, R2, revealing R1, R2
	return broadcast, unicast, nil
}

func (p *PreGenParticipant) Round3(broadcastInput network.RoundMessages[*Round2Broadcast], unicastInput network.RoundMessages[*Round2P2P]) (preProcessingMaterial *lindell22.PreProcessingMaterial, err error) {
	// Validation, unicastInput is delegated to przs.Round3
	if err := p.InRound(3); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessages(p.preSigners, p.IdentityKey(), broadcastInput); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 broadcast input")
	}

	BigR1 := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	BigR2 := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for identity := range p.preSigners.Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		inBroadcast, _ := broadcastInput.Get(identity)
		theirBigR1 := inBroadcast.BigR1
		theirBigR2 := inBroadcast.BigR2
		theirBigRWitness := inBroadcast.BigRWitness
		theirPid := identity.PublicKey().ToAffineCompressed()
		theirBigRCommitment, ok := p.state.theirBigRCommitment.Get(identity)
		if !ok {
			return nil, errs.NewMissing("BigR commitment of %x", theirPid)
		}

		// 1. verify commitment
		if err := commitments.Open(p.SessionId(), theirBigRCommitment, theirBigRWitness, []byte(commitmentDomainRLabel), theirBigR1.ToAffineCompressed(), theirBigR2.ToAffineCompressed(), theirPid, p.state.bigS); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// 2. verify dlog
		if err := dlogVerifyProof(inBroadcast.BigR1Proof, theirBigR1, p.SessionId(), p.state.bigS, p.nic, p.Transcript().Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}
		BigR1.Put(identity, theirBigR1)
		if err := dlogVerifyProof(inBroadcast.BigR2Proof, theirBigR2, p.SessionId(), p.state.bigS, p.nic, p.Transcript().Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}
		BigR2.Put(identity, theirBigR2)
	}

	seeds, err := p.przsSetupParticipant.Round3(unicastInput)
	if err != nil {
		return nil, errs.WrapFailed(err, "PRZS round 3 failed")
	}

	p.LastRound()
	return &lindell22.PreProcessingMaterial{
		PreSigners: p.preSigners,
		PrivateMaterial: &lindell22.PrivatePreProcessingMaterial{
			K1:    p.state.k1,
			K2:    p.state.k2,
			Seeds: seeds,
		},
		PreSignature: &lindell22.PreSignature{
			BigR1: BigR1,
			BigR2: BigR2,
		},
	}, nil
}

func dlogProve(x curves.Scalar, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript, prng io.Reader) (proof compiler.NIZKPoKProof, err error) {
	curve := x.ScalarField().Curve()
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	proof, statement, err := dlog.Prove(sessionId, x, curve.Generator(), nic, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create a proof")
	}
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}
	return proof, nil
}

func dlogVerifyProof(proof compiler.NIZKPoKProof, bigR curves.Point, sessionId, bigS []byte, nic compiler.Name, transcript transcripts.Transcript) (err error) {
	curve := bigR.Curve()
	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	if err := dlog.Verify(sessionId, proof, bigR, curve.Generator(), nic, transcript); err != nil {
		return errs.WrapVerification(err, "cannot verify proof")
	}
	return nil
}
