package fischlin

import (
	"encoding/binary"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ compiler.NIProver[sigma.Statement, sigma.Witness] = (*prover[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type prover[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sessionId     []byte
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
	rho           uint64
	b             uint64
	t             uint64
}

func (p *prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendMessages(rhoLabel, bitstring.ToBytesLE(int(p.rho)))
	p.transcript.AppendMessages(statementLabel, p.sigmaProtocol.SerializeStatement(statement))

	a := make([]byte, 0)
	aI := make([]A, p.rho)
	stateI := make([]S, p.rho)
	eI := make([][]byte, p.rho)
	zI := make([]Z, p.rho)

redo:
	for {
		for i := uint64(0); i < p.rho; i++ {
			var err error
			aI[i], stateI[i], err = p.sigmaProtocol.ComputeProverCommitment(statement, witness)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot generate commitment")
			}
			a = append(a, p.sigmaProtocol.SerializeCommitment(aI[i])...)
		}

		commonH, err := hashing.Hash(base.RandomOracleHashFunction, p.sigmaProtocol.SerializeStatement(statement), a, p.sessionId)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate commitment")
		}

		for i := uint64(0); i < p.rho; i++ {
			for j := uint64(0); j < (1 << p.t); j++ {
				eI[i], zI[i], err = p.sample(j, statement, witness, aI[i], stateI[i])
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot compute proof")
				}
				hb, err := hash(p.b, commonH, i, eI[i], p.sigmaProtocol.SerializeResponse(zI[i]))
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot compute proof")
				}
				if isAllZeros(hb) {
					break
				}
				if j == ((1 << p.t) - 1) {
					continue redo
				}
			}
		}

		break redo
	}

	commitmentSerialized := make([][]byte, 0)
	for i := uint64(0); i < p.rho; i++ {
		commitmentSerialized = append(commitmentSerialized, p.sigmaProtocol.SerializeCommitment(aI[i]))
	}
	responseSerialized := make([][]byte, 0)
	for i := uint64(0); i < p.rho; i++ {
		responseSerialized = append(responseSerialized, p.sigmaProtocol.SerializeResponse(zI[i]))
	}

	p.transcript.AppendMessages(commitmentLabel, commitmentSerialized...)
	p.transcript.AppendMessages(challengeLabel, eI...)
	p.transcript.AppendMessages(responseLabel, responseSerialized...)

	proof := &Proof[A, Z]{
		Rho: p.rho,
		B:   p.b,
		A:   aI,
		E:   eI,
		Z:   zI,
	}

	return proof, nil
}

func (p *prover[X, W, A, S, Z]) sample(t uint64, statement X, witness W, commitment A, state S) (e []byte, response Z, err error) {
	e = make([]byte, 8)
	binary.BigEndian.PutUint64(e, t)
	eBytes := make([]byte, p.sigmaProtocol.GetChallengeBytesLength())
	copy(eBytes[len(eBytes)-len(e):], e)
	z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, commitment, state, eBytes)
	if err != nil {
		return nil, z, errs.WrapFailed(err, "cannot compute z_i")
	}

	eLen := int((p.t + 7) / 8)
	return eBytes[len(eBytes)-eLen:], z, nil
}
