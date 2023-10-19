package hash2curve

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// HashToField hashes arbitrary-length byte strings to a list of one or more
// elements of a finite field F. It is used to generate curve points &| scalars.
// Reference Spec: https://datatracker.ietf.org/doc/html/rfc9380#section-5
func HashToField(h CurveHasher, m, log2p int, fieldOrder *saferith.Modulus, msg, dst []byte, count int) (u [][]*saferith.Nat, err error) {
	// step 1
	k := constants.ComputationalSecurity
	L := base.CeilDiv(log2p+k, 8)
	lenInBytes := count * m * L
	// step 2
	uniformBytes, err := h.ExpandMessage(msg, dst, lenInBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not expand message to be hashed to field")
	}
	u = make([][]*saferith.Nat, count)
	// step 3
	for i := 0; i < count; i++ {
		e := make([]*saferith.Nat, m)
		// step 4
		for j := 0; j < m; j++ {
			// step 5
			elmOffset := L * (j + i*m)
			// step 6
			tv := uniformBytes[elmOffset : elmOffset+L]
			// step 7
			tvNat := new(saferith.Nat).SetBytes(tv)
			e[j] = tvNat.Mod(tvNat, fieldOrder)
		}
		// step 8
		u[i] = e
	}
	// step 9
	return u, nil
}

// HashToCurveScalar hashes arbitrary-length byte strings `msg` to obtain `count`
// uniformly distributed scalars in the prime subgroup of `curve`.
func HashToCurveScalar(h CurveHasher, curve curves.Curve, msg, dst []byte, count int) (s []curves.Scalar, err error) {
	log2p := curve.Profile().SubGroupOrder().BitLen()
	subgroupOrder := curve.Profile().SubGroupOrder()
	u, err := HashToField(h, 1, log2p, subgroupOrder, msg, dst, count)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to scalar")
	}
	s = make([]curves.Scalar, len(u))
	for i := range u {
		if len(u[i]) != 1 {
			return nil, errs.NewFailed("hash to scalar returned a non-scalar")
		}
		s[i], err = curve.Scalar().SetNat(u[i][0])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not set scalar with nat")
		}
	}
	return s, nil
}

func HashToFieldElement(h CurveHasher, curve curves.Curve, msg []byte, count int) ([][]*saferith.Nat, error) {
	m := int(curve.Profile().Field().ExtensionDegree().Uint64())
	log2p := curve.Profile().Field().Characteristic().AnnouncedLen()
	fieldOrder := curve.Profile().Field().Order()
	dst := h.GenerateDST(curve)
	u, err := HashToField(h, m, log2p, fieldOrder, msg, dst, count)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to curve field")
	}
	return u, nil
}
