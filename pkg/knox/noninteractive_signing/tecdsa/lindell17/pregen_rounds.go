package lindell17

import (
	"bytes"
	"io"
	"strconv"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/curveutils"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/types"
	dlog "github.com/copperexchange/knox-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

type Round1Broadcast struct {
	BigRCommitment []commitments.Commitment

	_ helper_types.Incomparable
}

type Round2Broadcast struct {
	BigR        []curves.Point
	BigRProof   []*dlog.Proof
	BigRWitness []commitments.Witness

	_ helper_types.Incomparable
}

var commitmentHashFunc = sha3.New256

func (p *PreGenParticipant) Round1() (output *Round1Broadcast, err error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("rounds mismatch %d != 1", p.round)
	}

	k := make([]curves.Scalar, p.tau)
	bigR := make([]curves.Point, p.tau)
	bigRCommitment := make([]commitments.Commitment, p.tau)
	bigRWitness := make([]commitments.Witness, p.tau)

	for i := 0; i < p.tau; i++ {
		k[i] = p.cohortConfig.CipherSuite.Curve.Scalar().Random(p.prng)
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

func (p *PreGenParticipant) Round2(input map[helper_types.IdentityHash]*Round1Broadcast) (output *Round2Broadcast, err error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("rounds mismatch %d != 2", p.round)
	}

	theirBigRCommitments := make([]map[helper_types.IdentityHash]commitments.Commitment, p.tau)
	bigRProof := make([]*dlog.Proof, p.tau)

	for i := 0; i < p.tau; i++ {
		theirBigRCommitments[i] = make(map[helper_types.IdentityHash]commitments.Commitment)
		for _, identity := range p.cohortConfig.Participants.Iter() {
			if types.Equals(identity, p.myIdentityKey) {
				continue
			}
			in, ok := input[identity.Hash()]
			if !ok {
				return nil, errs.NewFailed("no input from all participants")
			}

			theirBigRCommitments[i][identity.Hash()] = in.BigRCommitment[i]
		}

		bigRProof[i], err = proveDlog(p.sid, p.transcript.Clone(), i, p.myIdentityKey, p.state.k[i], p.state.bigR[i], p.prng)
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

func (p *PreGenParticipant) Round3(input map[helper_types.IdentityHash]*Round2Broadcast) (preSignatureBatch *lindell17.PreSignatureBatch, err error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("rounds mismatch %d != 3", p.round)
	}

	commonBigR := make([]map[helper_types.IdentityHash]curves.Point, p.tau)
	for i := 0; i < p.tau; i++ {
		commonBigR[i] = make(map[helper_types.IdentityHash]curves.Point)

		for _, identity := range p.cohortConfig.Participants.Iter() {
			if types.Equals(identity, p.myIdentityKey) {
				continue
			}
			in, ok := input[identity.Hash()]
			if !ok {
				return nil, errs.NewFailed("no input from all participants")
			}

			if err := openCommitment(p.sid, i, identity, in.BigR[i], p.state.theirBigRCommitments[i][identity.Hash()], in.BigRWitness[i]); err != nil {
				return nil, errs.WrapFailed(err, "cannot open commitment to R")
			}
			if err := verifyDlogProof(p.sid, p.transcript.Clone(), i, identity, in.BigR[i], in.BigRProof[i]); err != nil {
				return nil, errs.WrapFailed(err, "cannot verify dlog R proof")
			}

			commonBigR[i][identity.Hash()] = in.BigR[i].Mul(p.state.k[i])
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
	c, w, err := commitments.Commit(commitmentHashFunc, commitmentMessage)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not commit the message")
	}
	return c, w, nil
}

func openCommitment(sid []byte, i int, party integration.IdentityKey, bigR curves.Point, bigRCommitment commitments.Commitment, bigRWitness commitments.Witness) error {
	commitmentMessage := bytes.Join([][]byte{sid, []byte(strconv.Itoa(i)), party.PublicKey().ToAffineCompressed(), bigR.ToAffineCompressed()}, nil)
	if err := commitments.Open(commitmentHashFunc, commitmentMessage, bigRCommitment, bigRWitness); err != nil {
		return errs.WrapVerificationFailed(err, "commitment could not be opened")
	}
	return nil
}

func proveDlog(sid []byte, transcript transcripts.Transcript, i int, party integration.IdentityKey, k curves.Scalar, bigR curves.Point, prng io.Reader) (proof *dlog.Proof, err error) {
	curveName := k.CurveName()
	curve, err := curveutils.GetCurveByName(curveName)
	if err != nil {
		return nil, errs.WrapFailed(err, "invalid curve %s", curveName)
	}

	transcript.AppendMessages("tau", []byte(strconv.Itoa(i)))
	transcript.AppendPoints("pid", party.PublicKey())
	prover, err := dlog.NewProver(curve.Generator(), sid, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct provererr")
	}

	proof, statement, err := prover.Prove(k)
	if err != nil {
		return nil, errs.WrapFailed(err, "prove operation failed")
	}
	if !bigR.Equal(statement) {
		return nil, errs.NewFailed("invalid proof statement")
	}

	return proof, nil
}

func verifyDlogProof(sid []byte, transcript transcripts.Transcript, i int, party integration.IdentityKey, bigR curves.Point, proof *dlog.Proof) (err error) {
	curveName := bigR.CurveName()
	curve, err := curveutils.GetCurveByName(curveName)
	if err != nil {
		return errs.WrapFailed(err, "invalid curve %s", curveName)
	}

	transcript.AppendMessages("tau", []byte(strconv.Itoa(i)))
	transcript.AppendPoints("pid", party.PublicKey())
	if err := dlog.Verify(curve.Generator(), bigR, proof, sid); err != nil {
		return errs.WrapVerificationFailed(err, "dlog verify failed")
	}
	return nil
}
