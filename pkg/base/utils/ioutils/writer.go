package ioutils

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"
)

// WriteConcat writes each byte slice to a writer and returns the total bytes written.
func WriteConcat[S ~[]byte](writer io.Writer, data ...S) (int, error) {
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
// both encoded as little-endian uint64 values, and returns total bytes written.
func WriteIndexLengthPrefixed[S ~[]byte](writer io.Writer, data ...S) (int, error) {
	n := 0
	for i, d := range data {
		l, err := writer.Write(uint64ToBytesLE(uint64(i)))
		if err != nil {
			return n, errs.Wrap(err)
		}
		n += l
		l, err = writer.Write(uint64ToBytesLE(uint64(len(d))))
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

// WriteLengthPrefixed writes each slice preceded by its length,
// encoded as little-endian uint64 values, and returns total bytes written.
func WriteLengthPrefixed[S ~[]byte](writer io.Writer, data ...S) (int, error) {
	n := 0
	for _, d := range data {
		l, err := writer.Write(uint64ToBytesLE(uint64(len(d))))
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

func uint64ToBytesLE(i uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], i)
	return b[:]
}
