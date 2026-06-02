package fiatshamir

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir/zkmodule"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

// prover implements the NIProver interface for Fiat-Shamir proofs.
type prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	ctx           *session.Context
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Prove generates a non-interactive proof for the given statement and witness.
// It delegates the transform to the zkmodule engine — commit, then derive the
// challenge from the transcript hash and compute the response — and returns the
// CBOR-serialised proof.
func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	a, s, err := zkmodule.Commit(p.sigmaProtocol, statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate commitment")
	}

	proof, err := zkmodule.Prove(p.ctx, p.sigmaProtocol, statement, witness, a, s)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate proof")
	}

	proofBytes, err := serde.MarshalCBOR(proof)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot serialise proof")
	}
	return proofBytes, nil
}
