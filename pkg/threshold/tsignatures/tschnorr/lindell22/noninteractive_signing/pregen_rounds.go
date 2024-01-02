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

type Round2Broadcast struct {
	BigR        []curves.Point
	BigR2       []curves.Point
	BigRWitness []commitments.Witness
	BigRProof   []*dlog.Proof
	BigR2Proof  []*dlog.Proof

	_ types.Incomparable
}

type Round2P2P struct {
	ZeroS []curves.Scalar

	_ types.Incomparable
}

func (p *PreGenParticipant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	k := make([]curves.Scalar, p.tau)
	k2 := make([]curves.Scalar, p.tau)
	bigR := make([]curves.Point, p.tau)
	bigR2 := make([]curves.Point, p.tau)
	bigRCommitment := make([]commitments.Commitment, p.tau)
	bigRWitness := make([]commitments.Witness, p.tau)
	for i := 0; i < p.tau; i++ {
		// 1. choose a random k & k2
		k[i], err = p.cohortConfig.CipherSuite.Curve.Scalar().Random(p.prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot generate random k")
		}
		k2[i], err = p.cohortConfig.CipherSuite.Curve.Scalar().Random(p.prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot generate random k2")
		}

		// 2. compute R = k * G, R2 = k2 * G
		bigR[i] = p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k[i])
		bigR2[i] = p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k2[i])

		// 3. compute Rcom = commit(R, R2, pid, sid, S)
		bigRCommitment[i], bigRWitness[i], err = commit(p.prng, bigR[i], bigR2[i], i, p.tau, p.state.pid, p.sid, p.state.bigS)
		if err != nil {
			return nil, errs.NewFailed("cannot commit to R")
		}
	}

	p.state.k = k
	p.state.k2 = k2
	p.state.bigR = bigR
	p.state.bigR2 = bigR2
	p.state.bigRWitness = bigRWitness

	p.round++
	return &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}, nil
}

func (p *PreGenParticipant) Round2(input map[types.IdentityHash]*Round1Broadcast) (outputBroadcast *Round2Broadcast, outputUnicast map[types.IdentityHash]*Round2P2P, err error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	theirBigRCommitment := make([]map[types.IdentityHash]commitments.Commitment, p.tau)
	zeroS := make([]map[types.IdentityHash]curves.Scalar, p.tau)
	bigRProof := make([]*dlog.Proof, p.tau)
	bigR2Proof := make([]*dlog.Proof, p.tau)
	for i := 0; i < p.tau; i++ {
		theirBigRCommitment[i] = make(map[types.IdentityHash]commitments.Commitment)
		zeroS[i] = make(map[types.IdentityHash]curves.Scalar)
		for _, identity := range p.cohortConfig.Participants.Iter() {
			if identity.Hash() == p.myAuthKey.Hash() {
				continue
			}

			in, ok := input[identity.Hash()]
			if !ok {
				return nil, nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			theirBigRCommitment[i][identity.Hash()] = in.BigRCommitment[i]

			zeroS[i][identity.Hash()], err = p.cohortConfig.CipherSuite.Curve.Scalar().Random(p.prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSampleFailed(err, "cannot generate random zero s")
			}
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
	}

	p.state.theirBigRCommitment = theirBigRCommitment
	p.state.zeroS = zeroS

	// 2. broadcast proof and opening of R, R2, revealing R, R2
	p.round++
	broadcast := &Round2Broadcast{
		BigR:        p.state.bigR,
		BigR2:       p.state.bigR2,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
		BigR2Proof:  bigR2Proof,
	}

	unicast := make(map[types.IdentityHash]*Round2P2P)
	for _, identity := range p.cohortConfig.Participants.Iter() {
		if identity.Hash() == p.myAuthKey.Hash() {
			continue
		}

		unicast[identity.Hash()] = &Round2P2P{ZeroS: make([]curves.Scalar, p.tau)}
		for k := 0; k < p.tau; k++ {
			unicast[identity.Hash()].ZeroS[k] = p.state.zeroS[k][identity.Hash()]
		}
	}

	return broadcast, unicast, nil
}

func (p *PreGenParticipant) Round3(broadcastInput map[types.IdentityHash]*Round2Broadcast, unicastInput map[types.IdentityHash]*Round2P2P) (preSignatureBatch *lindell22.PreSignatureBatch, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	bigR := make([]map[types.IdentityHash]curves.Point, p.tau)
	bigR2 := make([]map[types.IdentityHash]curves.Point, p.tau)
	theirZeroS := make([]map[types.IdentityHash]curves.Scalar, p.tau)
	for i := 0; i < p.tau; i++ {
		bigR[i] = make(map[types.IdentityHash]curves.Point)
		bigR2[i] = make(map[types.IdentityHash]curves.Point)
		theirZeroS[i] = make(map[types.IdentityHash]curves.Scalar)

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
			theirZeroS[i][identity.Hash()] = inUnicast.ZeroS[i]
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
			bigR[i][identity.Hash()] = theirBigR
			if err := dlogVerifyProof(inBroadcast.BigR2Proof[i], theirBigR2, i, p.sid, p.state.bigS, p.transcript.Clone()); err != nil {
				return nil, errs.WrapIdentifiableAbort(err, "cannot verify dlog proof from %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			bigR2[i][identity.Hash()] = theirBigR2
		}
	}

	preSignatures := make([]*lindell22.PreSignature, p.tau)
	for i := 0; i < p.tau; i++ {
		preSignatures[i] = &lindell22.PreSignature{
			K:          p.state.k[i],
			K2:         p.state.k2[i],
			BigR:       bigR[i],
			BigR2:      bigR2[i],
			MyZeroS:    p.state.zeroS[i],
			TheirZeroS: theirZeroS[i],
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
	curve := x.Curve()

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
