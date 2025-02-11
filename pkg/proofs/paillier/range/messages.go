package paillierrange

import (
	"math/big"

	"github.com/cronokirby/saferith"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
)

type Round1Output struct {
	ECommitment hashcommitments.Commitment

	_ ds.Incomparable
}

func (r1out *Round1Output) Validate() error {
	if r1out == nil {
		return errs.NewIsNil("round 1 output")
	}

	return nil
}

type Round2Output struct {
	C1 []*paillier.CipherText
	C2 []*paillier.CipherText

	_ ds.Incomparable
}

func (r2out *Round2Output) Validate(t int) error {
	if r2out == nil {
		return errs.NewIsNil("round 2 output")
	}
	if len(r2out.C1) != t {
		return errs.NewLength("C1 length (%d) != t (%d)", len(r2out.C1), t)
	}
	if len(r2out.C2) != t {
		return errs.NewLength("C2 length (%d) != t (%d)", len(r2out.C2), t)
	}
	for i := range t {
		if r2out.C1[i] == nil {
			return errs.NewIsNil("C1[%d]", i)
		}
		if r2out.C2[i] == nil {
			return errs.NewIsNil("C2[%d]", i)
		}
	}
	return nil
}

type Round3Output struct {
	E        *big.Int
	EWitness hashcommitments.Witness

	_ ds.Incomparable
}

type ZetZero struct {
	W1 *saferith.Nat
	R1 *saferith.Nat
	W2 *saferith.Nat
	R2 *saferith.Nat

	_ ds.Incomparable
}

func (z0 *ZetZero) Validate() error {
	if z0 == nil {
		return errs.NewIsNil("ZetZero")
	}
	if z0.W1 == nil {
		return errs.NewIsNil("W1")
	}
	if z0.R1 == nil {
		return errs.NewIsNil("R1")
	}
	if z0.W2 == nil {
		return errs.NewIsNil("W2")
	}
	if z0.R2 == nil {
		return errs.NewIsNil("R2")
	}
	return nil
}

type ZetOne struct {
	J        int
	XPlusWj  *saferith.Nat
	RTimesRj *saferith.Nat

	_ ds.Incomparable
}

func (z1 *ZetOne) Validate() error {
	if z1 == nil {
		return errs.NewIsNil("ZetOne")
	}
	if z1.J != 1 && z1.J != 2 {
		return errs.NewArgument("J (%d) not in {1,2}", z1.J)
	}
	if z1.XPlusWj == nil {
		return errs.NewIsNil("XPlusWj")
	}
	if z1.RTimesRj == nil {
		return errs.NewIsNil("RTimesRj")
	}
	return nil
}

type Round4Output struct {
	ZetZero map[int]*ZetZero
	ZetOne  map[int]*ZetOne

	_ ds.Incomparable
}

func (r4out *Round4Output) Validate(t int) error {
	if r4out == nil {
		return errs.NewIsNil("round 4 output")
	}
	if (len(r4out.ZetZero) + len(r4out.ZetOne)) != t {
		return errs.NewLength("ZetZero length (%d) != t (%d)", len(r4out.ZetZero)+len(r4out.ZetOne), t)
	}
	for i := range t {
		if r4out.ZetOne[i] == nil {
			if err := r4out.ZetZero[i].Validate(); err != nil {
				return errs.WrapValidation(err, "invalid ZetZero[%d]", i)
			}
		}
		if r4out.ZetZero[i] == nil {
			if err := r4out.ZetOne[i].Validate(); err != nil {
				return errs.WrapValidation(err, "invalid ZetOne[%d]", i)
			}
		}
	}
	return nil
}
