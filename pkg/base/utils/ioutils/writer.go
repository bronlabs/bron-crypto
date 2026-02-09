package ioutils

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"
)

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
