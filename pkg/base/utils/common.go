package utils

import (
	"bytes"
	"encoding/gob"
	"math/bits"
	"reflect"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"golang.org/x/exp/constraints"
)

func ParseOrderingFromSign[T constraints.Signed](x T) base.PartialOrdering {
	if x == 1 {
		return base.GreaterThan
	}
	if x == 0 {
		return base.Equal
	}
	if x == -1 {
		return base.LessThan
	}
	return base.Incomparable
}

func ParseOrderingFromMasks[F constraints.Integer](gt, eq, lt F) base.PartialOrdering {
	if gt != 0 {
		return base.GreaterThan
	}
	if eq != 0 {
		return base.Equal
	}
	if lt != 0 {
		return base.LessThan
	}
	return base.Incomparable
}

func Maybe[T any](f func(T) T) func(T) (T, error) {
	return func(t T) (T, error) {
		return f(t), nil
	}
}

func Maybe2[O, T1, T2 any](f func(T1, T2) O) func(T1, T2) (O, error) {
	return func(t1 T1, t2 T2) (O, error) {
		return f(t1, t2), nil
	}
}

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

// BoolTo casts a bool to any integer type.
func BoolTo[T constraints.Integer](b bool) T {
	if b {
		return 1
	}
	return 0
}

// CeilDiv returns `ceil(numerator/denominator) for integer inputs. Equivalently,
// it returns `x`, the smallest integer that satisfies `(x*b) >= a`.
func CeilDiv(numerator, denominator int) int {
	return (numerator - 1 + denominator) / denominator
}

// FloorLog2 return floor(log2(x)).
func FloorLog2(x int) int {
	return 63 - bits.LeadingZeros64(uint64(x))
}

// CeilLog2 return ceil(log2(x)).
func CeilLog2(x int) int {
	return 64 - bits.LeadingZeros64(uint64(x)-1)
}

func IsNil[T any](v T) bool {
	val := reflect.ValueOf(v)
	kind := val.Kind()
	return (kind == reflect.Ptr || kind == reflect.Interface) && val.IsNil()
}

// LeadingZeroBytes returns the count of 0x00 prefix bytes.
func LeadingZeroBytes(b []byte) int {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return i
}

func GobEncode[T any](v T) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(v)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot encode value")
	}
	return buf.Bytes(), nil
}

func GobDecode[T any](data []byte) (T, error) {
	dec := gob.NewDecoder(bytes.NewReader(data))
	var v T
	err := dec.Decode(&v)
	if err != nil {
		return v, errs.WrapSerialisation(err, "cannot decode value")
	}
	return v, nil
}
