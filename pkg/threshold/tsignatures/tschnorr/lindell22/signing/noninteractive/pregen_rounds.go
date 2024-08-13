package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
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

func (p *PreGenParticipant) Round1() (broadcastOutput *Round1Broadcast, err error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	// 1. choose a random k1 & k2
	k1, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate random k")
	}
	k2, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate random k2")
	}

	// 2. compute R1 = k1 * G, R2 = k2 * G
	bigR1 := p.Protocol.Curve().ScalarBaseMult(k1)
	bigR2 := p.Protocol.Curve().ScalarBaseMult(k2)

	// 3. compute Rcom = commit(R1, R2, pid, sessionId, S)
	crs := hashcommitments.CrsFromSessionId(p.SessionId, []byte(commitmentDomainRLabel), p.state.pid, p.state.bigS)
	committer := hashcommitments.NewScheme(crs)
	commitment, opening, err := committer.Commit(hashcommitments.Message{bigR1.ToAffineCompressed(), bigR2.ToAffineCompressed()}, p.Prng)
	if err != nil {
		return nil, errs.NewFailed("cannot commit to R")
	}

	broadcast := &Round1Broadcast{
		BigRCommitment: commitment,
	}

	p.state.k1 = k1
	p.state.k2 = k2
	p.state.bigR1 = bigR1
	p.state.bigR2 = bigR2
	p.state.opening = opening
	p.Round++

	return broadcast, nil
}

func (p *PreGenParticipant) Round2(broadcastInput network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast]) (broadcastOutput *Round2Broadcast, err error) {
	// Validation, unicastInput is delegated to przs.Round2A
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.preSigners, p.IdentityKey(), broadcastInput); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	}

	theirBigRCommitment := hashmap.NewHashableHashMap[types.IdentityKey, hashcommitments.Commitment]()
	for iterator := p.preSigners.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		inBroadcast, _ := broadcastInput.Get(identity)
		theirBigRCommitment.Put(identity, inBroadcast.BigRCommitment)
	}

	// 1. compute proof of dlog knowledge of R1 & R2
	bigR1Proof, err := dlogProve(p.state.k1, p.state.bigR1, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone(), p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}
	bigR2Proof, err := dlogProve(p.state.k2, p.state.bigR2, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone(), p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot prove dlog")
	}

	broadcast := &Round2Broadcast{
		BigR1:       p.state.bigR1,
		BigR2:       p.state.bigR2,
		BigROpening: p.state.opening,
		BigR1Proof:  bigR1Proof,
		BigR2Proof:  bigR2Proof,
	}
	p.state.theirBigRCommitment = theirBigRCommitment
	p.Round++

	// 2. broadcast proof and opening of R1, R2, revealing R1, R2
	return broadcast, nil
}

func (p *PreGenParticipant) Round3(broadcastInput network.RoundMessages[types.ThresholdProtocol, *Round2Broadcast]) (preProcessingMaterial *lindell22.PreProcessingMaterial, err error) {
	// Validation, unicastInput is delegated to przs.Round3
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.preSigners, p.IdentityKey(), broadcastInput); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input broadcast messages")
	}

	BigR1 := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	BigR2 := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for iterator := p.preSigners.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		inBroadcast, _ := broadcastInput.Get(identity)
		theirBigR1 := inBroadcast.BigR1
		theirBigR2 := inBroadcast.BigR2
		theirBigROpening := inBroadcast.BigROpening
		theirPid := identity.PublicKey().ToAffineCompressed()
		theirBigRCommitment, ok := p.state.theirBigRCommitment.Get(identity)
		if !ok {
			return nil, errs.NewMissing("BigR commitment of %x", theirPid)
		}

		// 1. verify commitment
		crs := hashcommitments.CrsFromSessionId(p.SessionId, []byte(commitmentDomainRLabel), theirPid, p.state.bigS)
		verifier := hashcommitments.NewScheme(crs)
		if err := verifier.Verify(hashcommitments.Message{theirBigR1.ToAffineCompressed(), theirBigR2.ToAffineCompressed()}, theirBigRCommitment, theirBigROpening); err != nil {
			return nil, errs.WrapFailed(err, "cannot open R commitment")
		}

		// 2. verify dlog
		if err := dlogVerifyProof(inBroadcast.BigR1Proof, theirBigR1, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}
		BigR1.Put(identity, theirBigR1)
		if err := dlogVerifyProof(inBroadcast.BigR2Proof, theirBigR2, p.SessionId, p.state.bigS, p.nic, p.Transcript.Clone()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "cannot verify dlog proof")
		}
		BigR2.Put(identity, theirBigR2)
	}

	p.Round++
	return &lindell22.PreProcessingMaterial{
		PreSigners: p.preSigners,
		PrivateMaterial: &lindell22.PrivatePreProcessingMaterial{
			K1: p.state.k1,
			K2: p.state.k2,
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
