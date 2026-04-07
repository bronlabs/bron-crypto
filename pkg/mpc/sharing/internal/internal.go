package internal

import "encoding/binary"

// ID uniquely identifies a shareholder. IDs must be non-zero for polynomial-based schemes
// since they serve as evaluation points.
type ID uint64

func (id ID) Bytes() []byte {
	return binary.LittleEndian.AppendUint64(nil, uint64(id))
}
