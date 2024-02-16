package fischlin

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
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
}

func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendMessages(statementLabel, p.sigmaProtocol.SerializeStatement(statement))

	a := make([]byte, 0)
	aI := make([]A, r)
	stateI := make([]S, r)

	// step 1. for each i in [r] compute SigmaP_a(x, w)
	for i := 0; i < r; i++ {
		var err error
		aI[i], stateI[i], err = p.sigmaProtocol.ComputeProverCommitment(statement, witness)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate commitment")
		}

		// step 2. set a = (a_i) for i in [r]
		a = append(a, p.sigmaProtocol.SerializeCommitment(aI[i])...)
	}

	eI := make([][]byte, r)
	zI := make([]Z, r)

	// step 3. for each i [r]
	for i := 0; i < r; i++ {
		// step 3.a set e to empty
		found := false
		twoToT := new(saferith.Nat).Lsh(new(saferith.Nat).SetUint64(t), t, 64)
		for e := new(saferith.Nat).SetUint64(0); isLess(e, twoToT); e = new(saferith.Nat).Add(e, new(saferith.Nat).SetUint64(1), 64) {
			eBytes := make([]byte, p.sigmaProtocol.GetChallengeBytesLength())
			copy(eBytes, bitstring.ReverseBytes(e.Bytes()))

			// ...and compute z_i = SigmaP_z(state_i, e_i)
			z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, aI[i], stateI[i], eBytes)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot generate response")
			}
			digest, err := hash(p.sessionId, a, bitstring.ToBytesLE(i), eBytes[:tBytes], p.sigmaProtocol.SerializeResponse(z))
			if err != nil {
				return nil, errs.WrapHashing(err, "cannot compute digest")
			}

			// step 3.c if hash(a, i, e_i, z_i) != 0 append e_i to e and repeat step 3.b
			if isAllZeros(digest) {
				eI[i] = eBytes
				zI[i] = z
				found = true
				break
			}
		}
		if !found {
			return nil, errs.NewFailed("abort")
		}
	}

	commitmentSerialized := make([]byte, 0)
	for i := 0; i < r; i++ {
		commitmentSerialized = append(commitmentSerialized, p.sigmaProtocol.SerializeCommitment(aI[i])...)
	}
	p.transcript.AppendMessages(commitmentLabel, commitmentSerialized)
	p.transcript.AppendMessages(challengeLabel, eI...)

	// step 4. output (a_i, e_i, z_i) for every i in [r]
	proof := &Proof[A, Z]{
		A: aI,
		E: eI,
		Z: zI,
	}
	return proof, nil
}
