package iknp03

import (
	"crypto/sha3"
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// prgLabel is the cSHAKE256 function name of the PRG.
const prgLabel = "BRON_CRYPTO-IKNP03-PRG"

// PRG expands one base-OT seed into the rows of the IKNP matrix. It is cSHAKE256
// with the seed as the input, prgLabel as the function name and the branch bit
// j followed by the little-endian base-OT index i as the customisation string,
// so every (seed, i, j) keys a distinct extendable output. It is a PRG when
// cSHAKE256 is modelled as a random oracle, which the one-message SoftSpokenOT
// built on top assumes anyway; the customisation only guards against accidental
// reuse of a seed under two roles, since every seed is a distinct input.
//
// One PRG lives for the whole life of its seed: every call to Read continues
// the output, so successive extensions consume disjoint segments. Both parties
// must read the same amount from the PRG of a given seed in every extension,
// which the protocol guarantees by reading l/8 bytes per row. Keccak has no
// data-dependent branches or table lookups, so the seed stays out of timing
// side channels. Not safe for concurrent use.
type PRG struct {
	xof *sha3.SHAKE
}

// NewPRG keys a PRG with the seed of base OT i and branch j ∈ {0, 1}. The seed
// must stay secret: whoever knows it reproduces the whole row.
func NewPRG(seed Seed, i int, j byte) (*PRG, error) {
	if i < 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("base OT index %d out of range", i)
	}
	if j > 1 {
		return nil, ot.ErrInvalidArgument.WithMessage("branch must be 0 or 1, got %d", j)
	}

	var customisation [9]byte
	customisation[0] = j
	binary.LittleEndian.PutUint64(customisation[1:], uint64(i))
	xof := sha3.NewCSHAKE256([]byte(prgLabel), customisation[:])
	if _, err := xof.Write(ot.MessageAsSlice(&seed)); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot absorb the seed")
	}
	return &PRG{xof: xof}, nil
}

// Read fills out with the next len(out) bytes of the output.
func (prg *PRG) Read(out []byte) (int, error) {
	if prg == nil || prg.xof == nil {
		return 0, ot.ErrInvalidArgument.WithMessage("prg must be initialised")
	}
	n, err := prg.xof.Read(out)
	if err != nil {
		return n, errs.Wrap(err).WithMessage("cannot squeeze the PRG")
	}
	return n, nil
}
