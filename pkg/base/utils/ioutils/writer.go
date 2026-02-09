package ioutils

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"
)

// WriteConcat writes each byte slice in order to writer and returns the total bytes written.
func WriteConcat(writer io.Writer, data ...[]byte) (int, error) {
	n := 0
	for _, d := range data {
		l, err := writer.Write(d)
		if err != nil {
			return n, errs.Wrap(err)
		}
		n += l
	}

	return n, nil
}

// WriteIndexLengthPrefixed writes each slice preceded by its index and length,
// both encoded as little-endian uint32 values, and returns total bytes written.
func WriteIndexLengthPrefixed(writer io.Writer, data ...[]byte) (int, error) {
	n := 0
	for i, d := range data {
		l, err := writer.Write(uint32ToBytesLE(uint32(i)))
		if err != nil {
			return n, errs.Wrap(err)
		}
		n += l
		l, err = writer.Write(uint32ToBytesLE(uint32(len(d))))
		if err != nil {
			return n, errs.Wrap(err)
		}
		n += l
		l, err = writer.Write(d)
		if err != nil {
			return n, errs.Wrap(err)
		}
		n += l
	}

	return n, nil
}

func uint32ToBytesLE(i uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], i)
	return b[:]
}
