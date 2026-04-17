package elog

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elcomop"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

// Name identifies the elog sigma protocol.
const Name sigma.Name = "PROOF_OF_KNOWLEDGE_DISCRETE_LOGARITHM_OF_ELGAMAL_COMMITMENT"

type (
	// Witness is the AND-composed witness (elcomop witness, Schnorr witness),
	// where the elcomop plaintext must equal g^y with y the Schnorr witness.
	Witness[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = sigand.WitnessCartesian[*elcomop.Witness[G, S], *schnorrpok.Witness[S]]

	// Statement is the AND-composed statement (elcomop commitment (L, M),
	// Schnorr public element Y).
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = sigand.StatementCartesian[*elcomop.Statement[G, S], *schnorrpok.Statement[G, S]]

	// State holds the prover's per-branch internal state.
	State[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = sigand.StateCartesian[*elcomop.State[G, S], *schnorrpok.State[S]]

	// Commitment is the prover's first message, pairing per-branch commitments.
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = sigand.CommitmentCartesian[*elcomop.Commitment[G, S], *schnorrpok.Commitment[G, S]]

	// Response is the prover's reply, pairing per-branch responses.
	Response[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = sigand.ResponseCartesian[*elcomop.Response[G, S], *schnorrpok.Response[S]]
)

// NewWitness composes an elcomop witness w1 = (M', lambda) with a Schnorr
// witness w2 = y into an elog witness. It enforces the elog binding M' = g^y,
// where g is the generator of the group the elcomop plaintext lives in, so
// that the resulting elcomop ciphertext (L, M) satisfies M = g^y * X^lambda.
func NewWitness[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](w1 *elcomop.Witness[G, S], w2 *schnorrpok.Witness[S]) (*Witness[G, S], error) {
	if w1 == nil || w2 == nil {
		return nil, ErrInvalidArgument.WithMessage("witnesses cannot be nil")
	}
	message, _ := w1.Value().Components()
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](message.Structure())
	if !message.Equal(group.ScalarBaseOp(w2.W)) {
		return nil, ErrInvalidArgument.WithMessage("invalid witness: Schnorr witness does not match ElGamal commitment witness")
	}
	out, err := sigand.CartesianComposeWitnesses(w1, w2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compose witnesses")
	}
	return out, nil
}

// NewStatement composes an elcomop statement (the ElGamal commitment (L, M))
// with a Schnorr statement (the public element Y) into an elog statement.
func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](x1 *elcomop.Statement[G, S], x2 *schnorrpok.Statement[G, S]) (*Statement[G, S], error) {
	if x1 == nil || x2 == nil {
		return nil, ErrInvalidArgument.WithMessage("statements cannot be nil")
	}
	out, err := sigand.CartesianComposeStatements(x1, x2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compose statements")
	}
	return out, nil
}

// Protocol is the elog sigma protocol, implemented as the AND-composition of
// elcomop and Schnorr. It satisfies sigma.Protocol for the composed
// statement/witness/commitment/state/response types.
type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	*sigand.ProtocolCartesian[
		*elcomop.Statement[G, S], *schnorrpok.Statement[G, S],
		*elcomop.Witness[G, S], *schnorrpok.Witness[S],
		*elcomop.Commitment[G, S], *schnorrpok.Commitment[G, S],
		*elcomop.State[G, S], *schnorrpok.State[S],
		*elcomop.Response[G, S], *schnorrpok.Response[S],
	]
}

// NewProtocol constructs the elog protocol for the given prime-order group,
// ElGamal public key bigX, and second independent generator h. The elcomop
// sub-protocol covers (L, M) with respect to bigX, and the Schnorr
// sub-protocol covers Y = h^y with base h.
func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], bigX *indcpacom.Key[*elgamal.PublicKey[G, S]], h G, prng io.Reader) (*Protocol[G, S], error) {
	elcomopProtocol, err := elcomop.NewProtocol(group, bigX, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal commitment opening protocol")
	}
	schnorrProtocol, err := schnorrpok.NewProtocol(h, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Schnorr protocol")
	}
	protocol, err := sigand.CartesianComposeNamed(Name, elcomopProtocol, schnorrProtocol)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compose protocols")
	}
	return &Protocol[G, S]{protocol}, nil
}
