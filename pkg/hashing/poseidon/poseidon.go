package poseidon

import (
	"hash"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
)

// ErrInvalidDataLength is returned when the input data length is not a multiple of 32 bytes.
var ErrInvalidDataLength = errs.New("invalid data length")

var (
	_ hash.Cloner = (*Poseidon)(nil)
)

// Poseidon implements the Poseidon hash function over the Pallas base field.
// It provides a sponge-based construction suitable for zero-knowledge proof systems.
type Poseidon struct {
	pristine bool
	state    *state
	buf      []*pasta.PallasBaseFieldElement
}

// NewKimchi creates a new Poseidon hasher with Kimchi parameters used by Mina Protocol.
func NewKimchi() *Poseidon {
	return &Poseidon{
		pristine: true,
		state:    newInitialState(poseidonParamsKimchiFp),
		buf:      nil,
	}
}

// NewLegacy creates a new Poseidon hasher with legacy parameters.
func NewLegacy() *Poseidon {
	return &Poseidon{
		pristine: true,
		state:    newInitialState(poseidonParamsLegacyFp),
		buf:      nil,
	}
}

// Rate returns the rate of the sponge construction (number of field elements absorbed per permutation).
func (p *Poseidon) Rate() int {
	return p.state.parameters.rate
}

// Update absorbs field elements into the sponge state and applies the permutation.
func (p *Poseidon) Update(xs ...*pasta.PallasBaseFieldElement) {
	if len(xs) == 0 {
		return
	}

	p.pristine = false
	p.buf = append(p.buf, xs...)
	for len(p.buf) >= p.Rate() {
		for i := range p.Rate() {
			p.state.v[i] = p.state.v[i].Add(p.buf[i])
		}
		p.state.Permute()
		p.buf = p.buf[p.Rate():]
	}
}

// Digest returns the current hash output as the first element of the state.
func (p *Poseidon) Digest() *pasta.PallasBaseFieldElement {
	stateClone := p.state.Clone()
	if p.pristine {
		stateClone.Permute()
		return stateClone.v[0]
	}

	if len(p.buf) > 0 {
		for i, b := range p.buf {
			stateClone.v[i] = stateClone.v[i].Add(b)
		}
		stateClone.Permute()
	}
	return stateClone.v[0]
}

func (p *Poseidon) CloneHasher() *Poseidon {
	return &Poseidon{
		pristine: p.pristine,
		state:    p.state.Clone(),
		buf:      slices.Clone(p.buf),
	}
}

// Write implements io.Writer by converting bytes to field elements and hashing them.
// The data length must be a multiple of 32 bytes.
func (p *Poseidon) Write(data []byte) (n int, err error) {
	if (len(data) % 32) != 0 {
		return 0, ErrInvalidDataLength.WithMessage("data length must be multiple of 32")
	}

	elems := []*pasta.PallasBaseFieldElement{}
	for i := range (len(data) + 31) / 32 {
		bytes := data[32*i : 32*(i+1)]
		fe, err := pasta.NewPallasBaseField().FromBytes(bytes)
		if err != nil {
			return 0, errs.Wrap(err).WithMessage("cannot create Pallas base field element")
		}
		elems = append(elems, fe)
	}
	p.Update(elems...)
	return len(data), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It implements hash.Hash.
func (p *Poseidon) Sum(data []byte) []byte {
	return append(data, p.Digest().Bytes()...)
}

// Reset resets the hasher to its initial state.
func (p *Poseidon) Reset() {
	p.pristine = true
	p.state = newInitialState(p.state.parameters)
	p.buf = nil
}

// Size returns the number of bytes in the hash output (32 bytes for a field element).
func (*Poseidon) Size() int {
	return 32
}

// BlockSize returns the hash's underlying block size in bytes.
func (*Poseidon) BlockSize() int {
	return 32
}

func (p *Poseidon) Clone() (hash.Cloner, error) {
	return p.CloneHasher(), nil
}
