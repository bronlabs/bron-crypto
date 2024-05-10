package pedersenveccomm

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

const Name = "PEDERSEN_VECTOR_COMMITMENT"

var (
	_ comm.Opening[Vector]     = (*Opening)(nil)
	_ veccomm.VectorCommitment = (*VectorCommitment)(nil)

	// hardcoded seed used to derive generators along with the session-id.
	somethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Message curves.Scalar
type Witness curves.Scalar
type Vector = veccomm.Vector[Message]

type Opening struct {
	vector  Vector
	witness Witness
}

type VectorCommitment struct {
	value  curves.Point
	length uint
}

// This function draw different generators through hash2curve chaining.
func (*vectorHomomorphicScheme) sampleGenerators(sessionId []byte, curve curves.Curve, n uint) ([]curves.Point, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	generators := make([]curves.Point, n)
	// Derive the initial point from session identifier and SomethingUpMySleeve
	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, somethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}
	for i := range generators {
		generators[i], err = curve.Hash(hBytes)
		if err != nil {
			return nil, errs.WrapHashing(err, "failed to hash to curve for H")
		}
		// Subsequent points are linked to the previous ones
		hBytes = append(hBytes, generators[i].ToAffineCompressed()...)
	}
	return generators, nil
}

func (o *Opening) Message() veccomm.Vector[Message] {
	return o.vector
}

func (vc *VectorCommitment) Length() uint {
	return vc.length
}

func (vc *VectorCommitment) Validate() error {
	if vc == nil {
		return errs.NewIsNil("receiver")
	}
	if vc.length == 0 {
		return errs.NewValidation("zero-length")
	}
	if !vc.value.IsInPrimeSubGroup() {
		return errs.NewMembership("commitment is not part of the prime order subgroup")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	return nil
}
