package lindell22

import (
	"bytes"
	"encoding/hex"
	"io"
	"strconv"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/commitments"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

const (
	commitmentDomainRLabel               = "Lindell2022PreGenR"
	transcriptDLogSLabel                 = "Lindell2022PreGenDLogS"
	transcriptDLogPreSignatureIndexLabel = "Lindell2022PreGenDLogPreSignatureIndex"
)

var commitmentHashFunc = sha3.New256

type Round1Broadcast struct {
	BigRCommitment []commitments.Commitment

	_ helper_types.Incomparable
}

type Round2Broadcast struct {
	BigR        []curves.Point
	BigRWitness []commitments.Witness
	BigRProof   []*dlog.Proof

	_ helper_types.Incomparable
}

func (p *PreGenParticipant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	k := make([]curves.Scalar, p.tau)
	bigR := make([]curves.Point, p.tau)
	bigRCommitment := make([]commitments.Commitment, p.tau)
	bigRWitness := make([]commitments.Witness, p.tau)
	for i := 0; i < p.tau; i++ {
		// 1. choose a random k
		k[i] = p.cohortConfig.CipherSuite.Curve.Scalar().Random(p.prng)

		// 2. compute R = k * G
		bigR[i] = p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k[i])

		// 3. compute Rcom = commit(R, pid, sid, S)
		bigRCommitment[i], bigRWitness[i], err = commit(bigR[i], i, p.tau, p.state.pid, p.sid, p.state.bigS)
		if err != nil {
			return nil, errs.NewFailed("cannot commit to R")
		}
	}

	p.state.k = k
	p.state.bigR = bigR
	p.state.bigRWitness = bigRWitness

	p.round++
	return &Round1Broadcast{
		BigRCommitment: bigRCommitment,
	}, nil
}

func (p *PreGenParticipant) Round2(input map[helper_types.IdentityHash]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	theirBigRCommitment := make([]map[helper_types.IdentityHash]commitments.Commitment, p.tau)
	bigRProof := make([]*dlog.Proof, p.tau)
	for i := 0; i < p.tau; i++ {
		theirBigRCommitment[i] = make(map[helper_types.IdentityHash]commitments.Commitment)
		for _, identity := range p.cohortConfig.Participants.Iter() {
			in, ok := input[identity.Hash()]
			if !ok {
				return nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			theirBigRCommitment[i][identity.Hash()] = in.BigRCommitment[i]
		}

		// 1. compute proof of dlog knowledge of R
		bigRProof[i], err = dlogProve(p.state.k[i], p.state.bigR[i], i, p.sid, p.state.bigS, p.transcript.Clone(), p.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot prove dlog")
		}
	}

	p.state.theirBigRCommitment = theirBigRCommitment

	// 2. broadcast proof and opening of R, revealing R
	p.round++
	return &Round2Broadcast{
		BigR:        p.state.bigR,
		BigRWitness: p.state.bigRWitness,
		BigRProof:   bigRProof,
	}, nil
}

func (p *PreGenParticipant) Round3(input map[helper_types.IdentityHash]*Round2Broadcast) (preSignatureBatch *lindell22.PreSignatureBatch, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	BigR := make([]map[helper_types.IdentityHash]curves.Point, p.tau)
	for i := 0; i < p.tau; i++ {
		BigR[i] = make(map[helper_types.IdentityHash]curves.Point)
		for _, identity := range p.cohortConfig.Participants.Iter() {
			in, ok := input[identity.Hash()]
			if !ok {
				return nil, errs.NewIdentifiableAbort("no input from participant %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}

			theirBigR := in.BigR[i]
			theirBigRWitness := in.BigRWitness[i]
			theirPid := identity.PublicKey().ToAffineCompressed()

			// 1. verify commitment
			if err := openCommitment(theirBigR, i, p.tau, theirPid, p.sid, p.state.bigS, p.state.theirBigRCommitment[i][identity.Hash()], theirBigRWitness); err != nil {
				return nil, errs.WrapFailed(err, "cannot open R commitment")
			}

			// 2. verify dlog
			if err := dlogVerifyProof(in.BigRProof[i], theirBigR, i, p.sid, p.state.bigS, p.transcript.Clone()); err != nil {
				return nil, errs.WrapIdentifiableAbort(err, "cannot verify dlog proof from %s", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()))
			}
			BigR[i][identity.Hash()] = theirBigR
		}
	}

	preSignatures := make([]*lindell22.PreSignature, p.tau)
	for i := 0; i < p.tau; i++ {
		preSignatures[i] = &lindell22.PreSignature{
			K:    p.state.k[i],
			BigR: BigR[i],
		}
	}

	return &lindell22.PreSignatureBatch{
		PreSignatures: preSignatures,
	}, nil
}

func commit(bigR curves.Point, i, tau int, pid, sid, bigS []byte) (commitment commitments.Commitment, witness commitments.Witness, err error) {
	message := bytes.Join([][]byte{[]byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), []byte(strconv.Itoa(i)), []byte(strconv.Itoa(tau)), pid, sid, bigS}, nil)
	commitment, witness, err = commitments.Commit(commitmentHashFunc, message)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to R")
	}

	return commitment, witness, nil
}

func openCommitment(bigR curves.Point, i, tau int, pid, sid, bigS []byte, commitment commitments.Commitment, witness commitments.Witness) (err error) {
	message := bytes.Join([][]byte{[]byte(commitmentDomainRLabel), bigR.ToAffineCompressed(), []byte(strconv.Itoa(i)), []byte(strconv.Itoa(tau)), pid, sid, bigS}, nil)
	if err := commitments.Open(commitmentHashFunc, message, commitment, witness); err != nil {
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
