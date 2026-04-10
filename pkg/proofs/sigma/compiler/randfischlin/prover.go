package randfischlin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

var _ compiler.NIProver[sigma.Witness, sigma.State] = (*prover[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

// prover implements the NIProver interface for randomised Fischlin proofs.
type prover[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	ctx           *session.Context
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

// Prove generates a non-interactive randomised Fischlin proof for the given statement
// and witness. It runs R parallel executions, randomly sampling challenges until
// finding ones that hash to zero. Returns the serialised proof containing all R transcripts.
func (p prover[X, W, A, S, Z]) Prove(witness W, prng io.Reader) (proofBytes compiler.NIZKPoKProof, err error) {
	if utils.IsNil(witness) || prng == nil {
		return nil, ErrNil.WithMessage("nil arguments")
	}
	statement, err := p.sigmaProtocol.DeriveStatement(witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot derive statement from witness")
	}

	sessionID := p.ctx.SessionID()
	p.ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	crs, err := p.ctx.Transcript().ExtractBytes(crsLabel, 32)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract crs")
	}
	p.ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())

	a := make([]byte, 0)
	aI := make([]A, R)
	stateI := make([]S, R)

	// step 1. for each i in [r] compute SigmaP_a(x, w)
	for i := range R {
		var err error
		stateI[i], err = p.sigmaProtocol.SampleProverState(witness, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample prover state")
		}
		aI[i], err = p.sigmaProtocol.ComputeProverCommitment(stateI[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot generate commitment")
		}

		// step 2. set a = (a_i) for i in [r]
		a = append(a, aI[i].Bytes()...)
	}

	eI := make([][]byte, R)
	zI := make([]Z, R)

	// step 3. for each i [r]
	for i := range R {
		// step 3.a set e to empty
		eSet := make([][]byte, 0)
		for {
			// gather some stats

			// step 3.b sample e_i...
			e, err := sample(eSet, p.sigmaProtocol.GetChallengeBytesLength(), p.prng)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot sample challenge bytes")
			}

			// ...and compute z_i = SigmaP_z(state_i, e_i)
			z, err := p.sigmaProtocol.ComputeProverResponse(witness, stateI[i], e)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot generate response")
			}
			digest, err := hash(crs, a, binary.LittleEndian.AppendUint64(nil, uint64(i)), e, z.Bytes())
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot compute digest")
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
	for i := range R {
		commitmentSerialized = append(commitmentSerialized, aI[i].Bytes()...)
	}
	p.ctx.Transcript().AppendBytes(commitmentLabel, commitmentSerialized)
	p.ctx.Transcript().AppendBytes(challengeLabel, eI...)

	// step 4. output (a_i, e_i, z_i) for every i in [r]
	proof := &Proof[A, Z]{
		A: aI,
		E: eI,
		Z: zI,
	}
	proofBytes, err = serde.MarshalCBOR(proof)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot serialise proof")
	}

	return proofBytes, nil
}
