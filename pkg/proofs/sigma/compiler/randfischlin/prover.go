package randfischlin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var _ compiler.NIProver[sigma.Statement, sigma.Witness] = (*prover[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type prover[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sessionId     network.SID
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (proofBytes compiler.NIZKPoKProof, err error) {
	p.transcript.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(p.sessionId[:])))
	crs, err := p.transcript.ExtractBytes(crsLabel, 32)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract crs")
	}
	p.transcript.AppendBytes(statementLabel, statement.Bytes())

	a := make([]byte, 0)
	aI := make([]A, R)
	stateI := make([]S, R)

	// step 1. for each i in [r] compute SigmaP_a(x, w)
	for i := 0; i < R; i++ {
		var err error
		aI[i], stateI[i], err = p.sigmaProtocol.ComputeProverCommitment(statement, witness)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate commitment")
		}

		// step 2. set a = (a_i) for i in [r]
		a = append(a, aI[i].Bytes()...)
	}

	eI := make([][]byte, R)
	zI := make([]Z, R)

	// step 3. for each i [r]
	for i := 0; i < R; i++ {
		// step 3.a set e to empty
		eSet := make([][]byte, 0)
		for {
			// gather some stats

			// step 3.b sample e_i...
			e, err := sample(eSet, p.sigmaProtocol.GetChallengeBytesLength(), p.prng)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "cannot sample challenge bytes")
			}

			// ...and compute z_i = SigmaP_z(state_i, e_i)
			z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, aI[i], stateI[i], e)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot generate response")
			}
			digest, err := hash(crs, a, binary.LittleEndian.AppendUint64(nil, uint64(i)), e, z.Bytes())
			if err != nil {
				return nil, errs.WrapHashing(err, "cannot compute digest")
			}

			// step 3.c if hash(a, i, e_i, z_i) != 0 append e_i to e and repeat step 3.b
			if isAllZeros(digest) {
				eI[i] = e
				zI[i] = z
				break
			}
			eSet = append(eSet, e)
		}
	}

	commitmentSerialized := make([]byte, 0)
	for i := 0; i < R; i++ {
		commitmentSerialized = append(commitmentSerialized, aI[i].Bytes()...)
	}
	p.transcript.AppendBytes(commitmentLabel, commitmentSerialized)
	p.transcript.AppendBytes(challengeLabel, eI...)

	// step 4. output (a_i, e_i, z_i) for every i in [r]
	proof := &Proof[A, Z]{
		A: aI,
		E: eI,
		Z: zI,
	}
	proofBytes, err = serde.MarshalCBOR(proof)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot serialise proof")
	}

	return proofBytes, nil
}
