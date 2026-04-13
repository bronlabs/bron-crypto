package poseidon

import (
	"hash"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
)

// ErrInvalidDataLength is returned when the input data length is not a multiple of 32 bytes.
var ErrInvalidDataLength = errs.New("invalid data length")

var (
	_ hash.Cloner = (*Poseidon)(nil)
)

// Poseidon implements the Poseidon hash function over the Pallas base field.
// It provides a sponge-based construction suitable for zero-knowledge proof systems.
type Poseidon struct {
	dirty bool
	state *state
}

// NewKimchi creates a new Poseidon hasher with Kimchi parameters used by Mina Protocol.
func NewKimchi() *Poseidon {
	return &Poseidon{
		dirty: false,
		state: newInitialState(poseidonParamsKimchiFp),
	}
}

// NewLegacy creates a new Poseidon hasher with legacy parameters.
func NewLegacy() *Poseidon {
	return &Poseidon{
		dirty: false,
		state: newInitialState(poseidonParamsLegacyFp),
	}
}

// Rate returns the rate of the sponge construction (number of field elements absorbed per permutation).
func (p *Poseidon) Rate() int {
	return p.state.parameters.rate
}

// Update absorbs field elements into the sponge state and applies the permutation.
// Note: The sponge absorbs field elements in rate-sized blocks, the callers must pad to full blocks before passing,
// and callers who need injective variable-length hashing must perform their own framing, length encoding,
// or domain separation before absorption.
func (p *Poseidon) Update(xs ...*pasta.PallasBaseFieldElement) error {
	if len(xs)%p.Rate() != 0 {
		return ErrInvalidDataLength.WithMessage("input must be multiple of the rate")
	}
	if len(xs) > 0 {
		p.dirty = true
	}

	for k := range len(xs) / p.Rate() {
		for i := range p.Rate() {
			p.state.v[i] = p.state.v[i].Add(xs[k*p.Rate()+i])
		}
		p.state.Permute()
	}
	return nil
}

// Digest returns the current hash output as the first element of the state.
func (p *Poseidon) Digest() *pasta.PallasBaseFieldElement {
	if p.dirty {
		return p.state.v[0].Clone()
	}

	clone := p.state.Clone()
	for i := range clone.parameters.rate {
		clone.v[i] = clone.v[i].Add(pasta.NewPallasBaseField().Zero())
	}
	clone.Permute()
	return clone.v[0].Clone()
}

func (p *Poseidon) CloneHasher() *Poseidon {
	return &Poseidon{
		dirty: p.dirty,
		state: p.state.Clone(),
	}
}

// Write implements io.Writer by converting bytes to field elements and hashing them.
// Note: The sponge absorbs bytes in rate-sized blocks, the callers must pad to full blocks before passing,
// and callers who need injective variable-length hashing must perform their own framing, length encoding,
// or domain separation before absorption, hence the data length must be a multiple of (32 * rate) bytes.
func (p *Poseidon) Write(data []byte) (n int, err error) {
	if len(data)%(p.Rate()*pastaImpl.FpBytes) != 0 {
		return 0, ErrInvalidDataLength.WithMessage("data length must be a multiple of the rate")
	}

	var elems []*pasta.PallasBaseFieldElement
	for i := range len(data) / pastaImpl.FpBytes {
		bytes := data[pastaImpl.FpBytes*i : pastaImpl.FpBytes*(i+1)]
		fe, err := pasta.NewPallasBaseField().FromBytes(bytes)
		if err != nil {
			return 0, errs.Wrap(err).WithMessage("cannot create Pallas base field element")
		}
		elems = append(elems, fe)
	}
	if err = p.Update(elems...); err != nil {
		return len(data), errs.Wrap(err).WithMessage("cannot update hasher")
	}

	return len(data), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It implements hash.Hash.
func (p *Poseidon) Sum(data []byte) []byte {
	return append(data, p.Digest().Bytes()...)
}

// Reset resets the hasher to its initial state.
func (p *Poseidon) Reset() {
	p.dirty = false
	p.state = newInitialState(p.state.parameters)
}

// Size returns the number of bytes in the hash output (32 bytes for a field element).
func (*Poseidon) Size() int {
	return 32
}

// BlockSize returns the hash's underlying block size in bytes.
func (p *Poseidon) BlockSize() int {
	return p.Rate() * pastaImpl.FpBytes
}

func (p *Poseidon) Clone() (hash.Cloner, error) {
	return p.CloneHasher(), nil
}
