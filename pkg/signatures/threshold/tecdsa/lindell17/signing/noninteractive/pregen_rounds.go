package noninteractive

import (
	"bytes"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"golang.org/x/crypto/sha3"
	"strconv"
)

type Round1Broadcast struct {
	BigRCommitment []commitments.Commitment
}

type Round2Broadcast struct {
	BigR        []curves.Point
	BigRProof   []*dlog.Proof
	BigRWitness []commitments.Witness
}

var (
	commitmentHashFunc = sha3.New256
)

func (p *PreGenParticipant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("rounds mismatch %d != 1", p.round)
	}

	k := make([]curves.Scalar, p.tau)
	bigR := make([]curves.Point, p.tau)
	bigRCommitment := make([]commitments.Commitment, p.tau)
	bigRWitness := make([]commitments.Witness, p.tau)

	for i := 0; i < p.tau; i++ {
		k[i] = p.cohortConfig.CipherSuite.Curve.NewScalar().Random(p.prng)
		bigR[i] = p.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k[i])
		bigRCommitment[i], bigRWitness[i], err = commit(p.sid, i, p.myIdentityKey, bigR[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot commit to R")
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

func (p *PreGenParticipant) Round2(input map[integration.IdentityKey]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("rounds mismatch %d != 2", p.round)
	}

	theirBigRCommitments := make([]map[integration.IdentityKey]commitments.Commitment, p.tau)
	bigRProof := make([]*dlog.Proof, p.tau)

	for i := 0; i < p.tau; i++ {
		theirBigRCommitments[i] = make(map[integration.IdentityKey]commitments.Commitment)
		for _, identity := range p.cohortConfig.Participants {
			if identity == p.myIdentityKey {
				continue
			}
			in, ok := input[identity]
			if !ok {
				return nil, errs.NewFailed("no input from all participants")
			}

			theirBigRCommitments[i][identity] = in.BigRCommitment[i]
		}

		bigRProof[i], err = proveDlog(p.sid, p.transcript.Clone(), i, p.myIdentityKey, p.state.k[i], p.state.bigR[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot proof R dlog")
		}
	}

	p.state.theirBigRCommitments = theirBigRCommitments

	p.round++
	return &Round2Broadcast{
		BigR:        p.state.bigR,
		BigRProof:   bigRProof,
		BigRWitness: p.state.bigRWitness,
	}, nil
}

func (p *PreGenParticipant) Round3(input map[integration.IdentityKey]*Round2Broadcast) (preSignatureBatch *lindell17.PreSignatureBatch, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("rounds mismatch %d != 3", p.round)
	}

	commonBigR := make([]map[integration.IdentityKey]curves.Point, p.tau)
	for i := 0; i < p.tau; i++ {
		commonBigR[i] = make(map[integration.IdentityKey]curves.Point)

		for _, identity := range p.cohortConfig.Participants {
			if identity == p.myIdentityKey {
				continue
			}
			in, ok := input[identity]
			if !ok {
				return nil, errs.NewFailed("no input from all participants")
			}

			if err := openCommitment(p.sid, i, identity, in.BigR[i], p.state.theirBigRCommitments[i][identity], in.BigRWitness[i]); err != nil {
				return nil, errs.WrapFailed(err, "cannot open commitment to R")
			}
			if err := verifyDlogProof(p.sid, p.transcript.Clone(), i, identity, in.BigR[i], in.BigRProof[i]); err != nil {
				return nil, errs.WrapFailed(err, "cannot verify dlog R proof")
			}

			commonBigR[i][identity] = in.BigR[i].Mul(p.state.k[i])
		}
	}

	preSignatures := make([]*lindell17.PreSignature, p.tau)
	for i := 0; i < p.tau; i++ {
		preSignatures[i] = &lindell17.PreSignature{
			K:    p.state.k[i],
			BigR: commonBigR[i],
		}
	}

	p.round++
	return &lindell17.PreSignatureBatch{
		PreSignatures: preSignatures,
	}, nil
}

func commit(sid []byte, i int, party integration.IdentityKey, bigR curves.Point) (commitments.Commitment, commitments.Witness, error) {
	commitmentMessage := bytes.Join([][]byte{sid, []byte(strconv.Itoa(i)), party.PublicKey().ToAffineCompressed(), bigR.ToAffineCompressed()}, nil)
	return commitments.Commit(commitmentHashFunc, commitmentMessage)
}

func openCommitment(sid []byte, i int, party integration.IdentityKey, bigR curves.Point, bigRCommitment commitments.Commitment, bigRWitness commitments.Witness) error {
	commitmentMessage := bytes.Join([][]byte{sid, []byte(strconv.Itoa(i)), party.PublicKey().ToAffineCompressed(), bigR.ToAffineCompressed()}, nil)
	return commitments.Open(commitmentHashFunc, commitmentMessage, bigRCommitment, bigRWitness)
}

func proveDlog(sid []byte, transcript transcript.Transcript, i int, party integration.IdentityKey, k curves.Scalar, bigR curves.Point) (proof *dlog.Proof, err error) {
	curveName := k.CurveName()
	curve, err := curves.GetCurveByName(curveName)
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid curve %s", curveName)
	}

	if err := transcript.AppendMessage([]byte("tau"), []byte(strconv.Itoa(i))); err != nil {
		return nil, errs.NewFailed("cannot write to transcript")
	}
	if err := transcript.AppendMessage([]byte("pid"), party.PublicKey().ToAffineCompressed()); err != nil {
		return nil, errs.NewFailed("cannot write to transcript")
	}
	prover, err := dlog.NewProver(curve.NewGeneratorPoint(), sid, transcript)
	if err != nil {
		return nil, err
	}

	proof, statement, err := prover.Prove(k)
	if err != nil {
		return nil, err
	}
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid proof statement")
	}

	return proof, nil
}

func verifyDlogProof(sid []byte, transcript transcript.Transcript, i int, party integration.IdentityKey, bigR curves.Point, proof *dlog.Proof) (err error) {
	curveName := bigR.CurveName()
	curve, err := curves.GetCurveByName(curveName)
	if err != nil {
		return errs.WrapFailed(err, "invalid curve %s", curveName)
	}

	if err := transcript.AppendMessage([]byte("tau"), []byte(strconv.Itoa(i))); err != nil {
		return errs.NewFailed("cannot write to transcript")
	}
	if err := transcript.AppendMessage([]byte("pid"), party.PublicKey().ToAffineCompressed()); err != nil {
		return errs.NewFailed("cannot write to transcript")
	}
	return dlog.Verify(curve.NewGeneratorPoint(), bigR, proof, sid, transcript)
}
