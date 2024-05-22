package pedersenvectorcommitments

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	pedersencommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	vc "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
)

const Name = "PEDERSEN_VECTOR_COMMITMENT"

var (
	_ commitments.Opening[Vector] = (*Opening)(nil)
	_ vc.VectorCommitment         = (*VectorCommitment)(nil)

	// hardcoded seed used to derive generators along with the session-id.
	somethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type VectorElement = pedersencommitments.Message
type Witness = pedersencommitments.Witness

type Vector []VectorElement

func (v Vector) Equal(w vc.Vector[VectorElement]) bool {
	ww, ok := w.(Vector)
	if !ok || len(v) != len(ww) {
		return false
	}
	for i, vi := range v {
		if !vi.Equal(ww[i]) {
			return false
		}
	}
	return true
}

type Opening struct {
	vector  Vector
	witness Witness
}

type VectorCommitment struct {
	value curves.Point
}

// This function draw different generators through hash2curve chaining.
func sampleGenerators(sessionId []byte, curve curves.Curve, n uint) ([]curves.Point, error) {
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

func (o *Opening) Message() Vector {
	return o.vector
}

func (vectorCommitment *VectorCommitment) Validate() error {
	if vectorCommitment == nil {
		return errs.NewIsNil("receiver")
	}
	if !vectorCommitment.value.IsInPrimeSubGroup() {
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
