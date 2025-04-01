package mina

import (
	"encoding/hex"
	"encoding/json"
	"github.com/bronlabs/bron-crypto/pkg/base/bitvec"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var (
	_ json.Marshaler = (*ROInput)(nil)
)

// ROInput handles the packing of bits and fields according to Mina spec, serves as a message.
type ROInput struct {
	fields []*pasta.PallasBaseFieldElement
	bits   *bitvec.BitVector
}

// TODO: implement something better
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

func (r *ROInput) Init() *ROInput {
	r.fields = make([]*pasta.PallasBaseFieldElement, 0)
	r.bits = bitvec.NewBitVector(make([]byte, 0), 0)
	return r
}

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

func (r *ROInput) AddFields(fieldElements ...*pasta.PallasBaseFieldElement) {
	r.fields = append(r.fields, fieldElements...)
}

func (r *ROInput) AddString(input string) {
	for _, b := range []byte(input) {
		for i := range 8 {
			bitIdx := 7 - i
			r.bits.Append((b >> bitIdx) & 1)
		}
	}
}

func (r *ROInput) AddBits(bits ...bool) {
	for _, b := range bits {
		if b {
			r.bits.Append(1)
		} else {
			r.bits.Append(0)
		}
	}
}

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
