package mina

import (
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/bitvec"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var (
	_ json.Marshaler = (*ROInput)(nil)
)

// ROInput (Random Oracle Input) is the message format for Mina signatures.
// It accumulates field elements and bits that are packed into Pallas base field
// elements for hashing with Poseidon.
//
// The ROInput format allows efficient representation of structured data for
// signing, where different parts of a transaction (amounts, addresses, etc.)
// can be added as field elements or packed bits.
//
// References:
//   - https://github.com/o1-labs/proof-systems/blob/43cf0ea4a66c3cccf40d29f13f36ba638e38ed4a/hasher/src/roinput.rs#L62
//   - https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/poseidon-bigint.ts#L68
type ROInput struct {
	fields []*pasta.PallasBaseFieldElement // Field elements added directly
	bits   *bitvec.BitVector               // Bits to be packed into field elements
}

// MarshalJSON serializes the ROInput to JSON as an array of hex-encoded field elements.
func (r *ROInput) MarshalJSON() ([]byte, error) {
	packed := r.PackToFields()
	fields := make([]string, len(packed))
	for i, p := range packed {
		fields[i] = hex.EncodeToString(p.Bytes())
	}

	b, err := json.Marshal(fields)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot serialise input")
	}
	return b, nil
}

// Init initializes an empty ROInput. Must be called before use.
func (r *ROInput) Init() *ROInput {
	r.fields = make([]*pasta.PallasBaseFieldElement, 0)
	r.bits = bitvec.NewBitVector(make([]byte, 0), 0)
	return r
}

// Clone creates a deep copy of the ROInput.
func (r *ROInput) Clone() *ROInput {
	t := new(ROInput)
	t.fields = make([]*pasta.PallasBaseFieldElement, len(r.fields))
	for i, f := range r.fields {
		t.fields[i] = f.Clone()
	}
	buffer := r.bits.Bytes()
	data := make([]byte, len(buffer))
	copy(data, buffer)
	t.bits = bitvec.NewBitVector(data, r.bits.Length())
	return t
}

// AddFields appends field elements directly to the ROInput.
// These will appear first when packed for hashing.
func (r *ROInput) AddFields(fieldElements ...*pasta.PallasBaseFieldElement) {
	r.fields = append(r.fields, fieldElements...)
}

// AddString appends a string as bits (MSB first per byte).
func (r *ROInput) AddString(input string) {
	for _, b := range []byte(input) {
		for i := range 8 {
			bitIdx := 7 - i
			r.bits.Append((b >> bitIdx) & 1)
		}
	}
}

// AddBits appends individual bits to the ROInput.
func (r *ROInput) AddBits(bits ...bool) {
	for _, b := range bits {
		if b {
			r.bits.Append(1)
		} else {
			r.bits.Append(0)
		}
	}
}

// PackToFields converts the ROInput to field elements for Poseidon hashing.
// Field elements are included directly, while accumulated bits are packed
// into 254-bit chunks (the maximum that fits in a Pallas field element).
func (r *ROInput) PackToFields() []*pasta.PallasBaseFieldElement {
	const maxChunkSize = 254
	fields := make([]*pasta.PallasBaseFieldElement, 0, len(r.fields)+((r.bits.Length()+maxChunkSize-1)/maxChunkSize))
	for _, f := range r.fields {
		fields = append(fields, f.Clone())
	}

	idx := 0
	for idx < r.bits.Length() {
		var chunk [32]byte
		for i := 0; i < maxChunkSize && idx < r.bits.Length(); i++ {
			offset := idx % maxChunkSize
			byteIdx := offset / 8
			bitIdx := offset % 8
			chunk[byteIdx] |= r.bits.Element(idx) << bitIdx
			idx++
		}
		slices.Reverse(chunk[:])
		field, _ := pasta.NewPallasBaseField().FromBytes(chunk[:])
		fields = append(fields, field)
	}

	return fields
}

// BitsLength returns the number of bits currently stored
func (r *ROInput) BitsLength() int {
	if r.bits == nil {
		return 0
	}
	return r.bits.Length()
}

// BitsBytes returns the raw bytes of the bit vector
func (r *ROInput) BitsBytes() []byte {
	if r.bits == nil {
		return nil
	}
	return r.bits.Bytes()
}
