package fischlin

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var _ compiler.NIProver[sigma.Statement, sigma.Witness] = (*prover[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

// prover implements the NIProver interface for Fischlin proofs.
type prover[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sessionId     network.SID
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
	rho           uint64
	b             uint64
	t             uint64
}

// Prove generates a non-interactive Fischlin proof for the given statement and witness.
// It runs rho parallel executions of the sigma protocol, searching for challenge/response
// pairs that hash to zero. Returns the serialized proof containing all rho transcripts.
func (p *prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendBytes(rhoLabel, binary.LittleEndian.AppendUint64(nil, p.rho))
	p.transcript.AppendBytes(statementLabel, statement.Bytes())
	commonHKey, err := p.transcript.ExtractBytes(commonHLabel, base.CollisionResistanceBytesCeil)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot extract h")
	}

	a := make([]byte, 0)
	aI := make([]A, p.rho)
	stateI := make([]S, p.rho)
	eI := make([][]byte, p.rho)
	zI := make([]Z, p.rho)

redo:
	for {
		// 1. For i = 1, ..., ρ:
		for i := uint64(0); i < p.rho; i++ {
			var err error

			// 1.a. compute (m_i, σ_i) ← ProverFirstMessage(x, w) independently for each i
			aI[i], stateI[i], err = p.sigmaProtocol.ComputeProverCommitment(statement, witness)
			if err != nil {
				return nil, errs2.Wrap(err).WithMessage("cannot generate commitment")
			}

			a = append(a, aI[i].Bytes()...)
		}

		// 3. common-h ← H(x, m, sid)
		// (This is a full hash, with output length 2*κc)
		commonH, err := hashing.Hash(randomOracle, commonHKey, statement.Bytes(), a, p.sessionId[:])
		if err != nil {
			return nil, errs2.Wrap(err).WithMessage("cannot generate commitment")
		}

		// 4. For i = 1, ..., ρ:
		for i := uint64(0); i < p.rho; i++ {
			// 4.a. For ei = 0, ..., 2^t − 1:
			for j := uint64(0); j < (1 << p.t); j++ {
				// 4.a.i. z_i ← ProverSecondMessage(x, w, σ_i, e_i)
				eI[i], zI[i], err = p.challengeBytesAndResponse(j, statement, witness, aI[i], stateI[i])
				if err != nil {
					return nil, errs2.Wrap(err).WithMessage("cannot compute proof")
				}

				// 4.a.ii. h_i ← H(common-h, i, e_i, z_i), where H is the first b bits of output of hash
				hI, err := hash(p.b, commonH, i, eI[i], zI[i].Bytes())
				if err != nil {
					return nil, errs2.Wrap(err).WithMessage("cannot compute proof")
				}

				// 4.a.iii. If hi == 0, break
				if isAllZeros(hI) {
					break
				}

				// 4.a.iv. If e_i == 2^t − 1, redo the entire proof from the beginning
				// (If this occurs, then it means that no break ever took place, meaning that the proof failed)
				if j == ((1 << p.t) - 1) {
					continue redo
				}
			}
		}

		break redo
	}

	commitmentSerialized := make([][]byte, 0)
	for i := uint64(0); i < p.rho; i++ {
		commitmentSerialized = append(commitmentSerialized, aI[i].Bytes())
	}
	responseSerialized := make([][]byte, 0)
	for i := uint64(0); i < p.rho; i++ {
		responseSerialized = append(responseSerialized, zI[i].Bytes())
	}
	p.transcript.AppendBytes(commitmentLabel, commitmentSerialized...)
	p.transcript.AppendBytes(challengeLabel, eI...)
	p.transcript.AppendBytes(responseLabel, responseSerialized...)

	// 7. π ← (m, e, z)
	proof := &Proof[A, Z]{
		Rho: p.rho,
		B:   p.b,
		A:   aI, // 2. m ← (m_1, ..., m_ρ)
		E:   eI, // 5. e ← (e_1, ..., e_ρ)
		Z:   zI, // 6. z ← (z_1, ..., z_ρ)
	}
	proofBytes, err := serde.MarshalCBOR(proof)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot serialise proof")
	}

	// 8. Output π
	return proofBytes, nil
}

func (p *prover[X, W, A, S, Z]) challengeBytesAndResponse(t uint64, statement X, witness W, commitment A, state S) (e []byte, response Z, err error) {
	e = make([]byte, 8)
	binary.BigEndian.PutUint64(e, t)
	eBytes := make([]byte, p.sigmaProtocol.GetChallengeBytesLength())
	copy(eBytes[len(eBytes)-len(e):], e)
	z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, commitment, state, eBytes)
	if err != nil {
		return nil, z, errs2.Wrap(err).WithMessage("cannot compute z_i")
	}

	eLen := int((p.t + 7) / 8)
	return eBytes[len(eBytes)-eLen:], z, nil
}
