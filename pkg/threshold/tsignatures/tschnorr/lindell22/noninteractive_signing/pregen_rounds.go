package noninteractive_signing

import (
	"encoding/hex"
	"io"
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	dlog "github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	commitmentDomainRLabel               = "Lindell2022PreGenR"
	transcriptDLogSLabel                 = "Lindell2022PreGenDLogS"
	transcriptDLogPreSignatureIndexLabel = "Lindell2022PreGenDLogPreSignatureIndex"
)

type Round1Broadcast struct {
	BigRCommitment []commitments.Commitment

	_ types.Incomparable
}

type Round1P2P struct {
	przs []*setup.Round1P2P

	_ types.Incomparable
}

type Round2Broadcast struct {
	BigR        []curves.Point
	BigR2       []curves.Point
	BigRWitness []commitments.Witness
	BigRProof   []*dlog.Proof
	BigR2Proof  []*dlog.Proof

	_ types.Incomparable
}

type Round2P2P struct {
	przs []*setup.Round2P2P
}

func (p *PreGenParticipant) Round1() (broadcastOutput *Round1Broadcast, unicastOutput map[types.IdentityHash]*Round1P2P, err error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	k := make([]curves.Scalar, p.tau)
	k2 := make([]curves.Scalar, p.tau)
	bigR := make([]curves.Point, p.tau)
	bigR2 := make([]curves.Point, p.tau)
	bigRCommitment := make([]commitments.Commitment, p.tau)
	bigRWitness := make([]commitments.Witness, p.tau)
	przsOutputs := make([]map[types.IdentityHash]*setup.Round1P2P, p.tau)
	for i := 0; i < p.tau; i++ {
		// 1. choose a random k & k2
		k[i], err = p.cohortConfig.CipherSuite.Curve.ScalarField().Random(p.prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSampleFailed(err, "cannot generate random k")
		}
		k2[i], err = p.cohortConfig.CipherSuite.Curve.ScalarField().Random(p.prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSampleFailed(err, "cannot generate random k2")
		}

		// 2. compute R = k * G, R2 = k2 * G
		bigR[i] = p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k[i])
		bigR2[i] = p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k2[i])

		// 3. compute Rcom = commit(R, R2, pid, sid, S)
		bigRCommitment[i], bigRWitness[i], err = commit(p.prng, bigR[i], bigR2[i], i, p.tau, p.state.pid, p.sid, p.state.bigS)
		if err != nil {
			return nil, nil, errs.NewFailed("cannot commit to R")
		}

		przsOutputs[i], err = p.przsSetupParticipants[i].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "PRZS round 1 failed")
		}
	}

	broadcast := &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}
	unicast := make(map[types.IdentityHash]*Round1P2P)
	for hash := range p.cohortConfig.Participants.Iter() {
		if hash == p.myAuthKey.Hash() {
			continue
		}
		unicast[hash] = &Round1P2P{
			przs: make([]*setup.Round1P2P, p.tau),
		}
		for t := 0; t < p.tau; t++ {
			unicast[hash].przs[t] = przsOutputs[t][hash]
		}
	}

	p.state.k = k
	p.state.k2 = k2
	p.state.bigR = bigR
	p.state.bigR2 = bigR2
	p.state.bigRWitness = bigRWitness
	p.round++

	return broadcast, unicast, nil
}

func (p *PreGenParticipant) Round2(broadcastInput map[types.IdentityHash]*Round1Broadcast, unicastInput map[types.IdentityHash]*Round1P2P) (broadcastOutput *Round2Broadcast, unicastOutput map[types.IdentityHash]*Round2P2P, err error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	theirBigRCommitment := make([]map[types.IdentityHash]commitments.Commitment, p.tau)
	bigRProof := make([]*dlog.Proof, p.tau)
	bigR2Proof := make([]*dlog.Proof, p.tau)
	przsOutputs := make([]map[types.IdentityHash]*setup.Round2P2P, p.tau)
	for i := 0; i < p.tau; i++ {
		theirBigRCommitment[i] = make(map[types.IdentityHash]commitments.Commitment)
		przsInput := make(map[types.IdentityHash]*setup.Round1P2P)

		for _, identity := range p.cohortConfig.Participants.Iter() {
			if identity.Hash() == p.myAuthKey.Hash() {
				continue
			}

			inBroadcast, ok := broadcastInput[identity.Hash()]
			if !ok {
				return nil, nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			inUnicast, ok := unicastInput[identity.Hash()]
			if !ok {
				return nil, nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}

			theirBigRCommitment[i][identity.Hash()] = inBroadcast.BigRCommitment[i]
			przsInput[identity.Hash()] = inUnicast.przs[i]
		}

		// 1. compute proof of dlog knowledge of R & R2
		bigRProof[i], err = dlogProve(p.state.k[i], p.state.bigR[i], i, p.sid, p.state.bigS, p.transcript.Clone(), p.prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
		}
		bigR2Proof[i], err = dlogProve(p.state.k2[i], p.state.bigR2[i], i, p.sid, p.state.bigS, p.transcript.Clone(), p.prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot prove dlog")
		}

		przsOutputs[i], err = p.przsSetupParticipants[i].Round2(przsInput)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "PRZS round 2 failed")
		}
	}

	broadcast := &Round2Broadcast{
		BigR:        p.state.bigR,
		BigR2:       p.state.bigR2,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
		BigR2Proof:  bigR2Proof,
	}
	unicast := make(map[types.IdentityHash]*Round2P2P)
	for hash := range p.cohortConfig.Participants.Iter() {
		if hash == p.myAuthKey.Hash() {
			continue
		}
		unicast[hash] = &Round2P2P{
			przs: make([]*setup.Round2P2P, p.tau),
		}
		for t := 0; t < p.tau; t++ {
			unicast[hash].przs[t] = przsOutputs[t][hash]
		}
	}

	p.state.theirBigRCommitment = theirBigRCommitment
	p.round++

	// 2. broadcast proof and opening of R, R2, revealing R, R2
	return broadcast, unicast, nil
}

func (p *PreGenParticipant) Round3(broadcastInput map[types.IdentityHash]*Round2Broadcast, unicastInput map[types.IdentityHash]*Round2P2P) (preSignatureBatch *lindell22.PreSignatureBatch, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	BigR := make([]map[types.IdentityHash]curves.Point, p.tau)
	BigR2 := make([]map[types.IdentityHash]curves.Point, p.tau)
	seeds := make([]przs.PairwiseSeeds, p.tau)
	for i := 0; i < p.tau; i++ {
		BigR[i] = make(map[types.IdentityHash]curves.Point)
		BigR2[i] = make(map[types.IdentityHash]curves.Point)
		przsInput := make(map[types.IdentityHash]*setup.Round2P2P)
		for _, identity := range p.cohortConfig.Participants.Iter() {
			if identity.Hash() == p.myAuthKey.Hash() {
				continue
			}

			inBroadcast, ok := broadcastInput[identity.Hash()]
			if !ok {
				return nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			inUnicast, ok := unicastInput[identity.Hash()]
			if !ok {
				return nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}

			theirBigR := inBroadcast.BigR[i]
			theirBigR2 := inBroadcast.BigR2[i]
			theirBigRWitness := inBroadcast.BigRWitness[i]
			theirPid := identity.PublicKey().ToAffineCompressed()

			// 1. verify commitment
			if err := openCommitment(theirBigR, theirBigR2, i, p.tau, theirPid, p.sid, p.state.bigS, p.state.theirBigRCommitment[i][identity.Hash()], theirBigRWitness); err != nil {
				return nil, errs.WrapFailed(err, "cannot open R commitment")
			}

			// 2. verify dlog
			if err := dlogVerifyProof(inBroadcast.BigRProof[i], theirBigR, i, p.sid, p.state.bigS, p.transcript.Clone()); err != nil {
				return nil, errs.WrapIdentifiableAbort(err, "cannot verify dlog proof from %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			BigR[i][identity.Hash()] = theirBigR
			if err := dlogVerifyProof(inBroadcast.BigR2Proof[i], theirBigR2, i, p.sid, p.state.bigS, p.transcript.Clone()); err != nil {
				return nil, errs.WrapIdentifiableAbort(err, "cannot verify dlog proof from %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			BigR2[i][identity.Hash()] = theirBigR2

			przsInput[identity.Hash()] = inUnicast.przs[i]
		}

		seeds[i], err = p.przsSetupParticipants[i].Round3(przsInput)
		if err != nil {
			return nil, errs.WrapFailed(err, "PRZS round 1 failed")
		}
	}

	preSignatures := make([]*lindell22.PreSignature, p.tau)
	for i := 0; i < p.tau; i++ {
		preSignatures[i] = &lindell22.PreSignature{
			K:     p.state.k[i],
			K2:    p.state.k2[i],
			BigR:  BigR[i],
			BigR2: BigR2[i],
			Seeds: seeds[i],
		}
	}

	return &lindell22.PreSignatureBatch{
		PreSignatures: preSignatures,
	}, nil
}

func commit(prng io.Reader, bigR, bigR2 curves.Point, i, tau int, pid, sid, bigS []byte) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	commitment, witness, err = commitments.Commit(sid, prng, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), bigR2.ToAffineCompressed(), []byte(strconv.Itoa(i)), []byte(strconv.Itoa(tau)), pid, bigS)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to R")
	}

	return commitment, witness, nil
}

func openCommitment(bigR, bigR2 curves.Point, i, tau int, pid, sid, bigS []byte, commitment commitments.Commitment, witness commitments.Witness) (err error) {
	if err := commitments.Open(sid, commitment, witness, []byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), bigR2.ToAffineCompressed(), []byte(strconv.Itoa(i)), []byte(strconv.Itoa(tau)), pid, bigS); err != nil {
		return errs.WrapVerificationFailed(err, "cannot open commitment")
	}

	return nil
}

func dlogProve(x curves.Scalar, bigR curves.Point, presigIndex int, sid, bigS []byte, transcript transcripts.Transcript, prng io.Reader) (proof *dlog.Proof, err error) {
	curve := x.ScalarField().Curve()

	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	transcript.AppendMessages(transcriptDLogPreSignatureIndexLabel, []byte(strconv.Itoa(presigIndex)))

	prover, err := dlog.NewProver(curve.Generator(), sid, transcript, prng)
	if err != nil {
		return nil, errs.NewFailed("cannot create dlog prover")
	}
	proof, statement, err := prover.Prove(x)
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid statement")
	}
	if err != nil {
		return nil, errs.NewFailed("cannot create a proof")
	}

	return proof, nil
}

func dlogVerifyProof(proof *dlog.Proof, bigR curves.Point, presigIndex int, sid, bigS []byte, transcript transcripts.Transcript) (err error) {
	curve := bigR.Curve()

	transcript.AppendMessages(transcriptDLogSLabel, bigS)
	transcript.AppendMessages(transcriptDLogPreSignatureIndexLabel, []byte(strconv.Itoa(presigIndex)))
	if err := dlog.Verify(curve.Generator(), bigR, proof, sid); err != nil {
		return errs.WrapVerificationFailed(err, "cannot verify commitment")
	}

	return nil
}
