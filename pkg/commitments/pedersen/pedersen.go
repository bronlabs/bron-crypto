package pedersen

import (
	crand "crypto/rand"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

// Define the types for Message, Commitment, and Witness
type Message curves.Scalar
type Commitment curves.Point
type Witness curves.Scalar

// PedersenCommitment implements the Commitment interface
type PedersenCommitmentScheme struct{}

// Commit generates a commitment and a witness from a message
func (pcs *PedersenCommitmentScheme) Commit(sessionId []byte, message Message) (Commitment, Witness, error) {
	// Generate a random scalar for the witness
	witness := message.ScalarField().Random(crand.Reader)
	if err != nil {
		return Commitment{}, nil, err
	}
	// Generate the 1st operand of the commitment
	mG := message.Curve().Generator().Mul(message)
	// Generate a random point from the sessionId and 'NothingUpMySleeve'
	HMessage, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, []byte(NothingUpMySleeve))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce dlog of H")
	}
	H, err := protocol.Curve().Hash(HMessage)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	// Generate the 2nd operand of the commitment
	rH := H.Mul(witness)
	commitment := rD.Add(mG)
	return commitment, witness, nil
}

// Open verifies a commitment against a message and a witness
func (pcs *PedersenCommitmentScheme) Open(sessionId []byte, commitment Commitment, witness Witness, message Message) error {
	// Reconstructs mG
	mG := message.Curve().Generator().Mul(message)
	// Reconstructs rH
	HMessage, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, []byte(NothingUpMySleeve))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce dlog of H")
	}
	H, err := protocol.Curve().Hash(HMessage)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	rH := H.Mul(witness)
	// Reconstructs the corresponding commitment
	expectedCommitment := rD.Add(mG)
	// Check whether it matches the commitment given as input
	if commitment != expectedCommitment {
		return fmt.Errorf("Opening failed")
	}
	return nil
}
