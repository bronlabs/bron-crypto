// Package safecast provides some utilities to avoid risk of unexpected behaviour
// due to go casting semantics. Additionally it provides a way to silence the gosec
// G115 alerts.
//
// There are 2 modes of operation
// 1. Use To{Type} functions to convert to a type but provide an OutOfBounds error
// if an overflow is expected. It will still return the cast value in case of error as we may want to
// maintain behaviour of golang.
//
// 2. Use Must(To{Type}) combination to force panic if OutOfBounds error found.
package safecast

import (
	"errors"
	"math"

	"golang.org/x/exp/constraints"
)

var ErrOutOfBounds = errors.New("casting value out of bounds")

func ToUint8[T constraints.Integer](in T) (out uint8, err error) {
	out = uint8(in)

	if uint64(in) > math.MaxUint8 || in < 0 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToUint8[T constraints.Integer](in T) uint8 {
	return Must(ToUint8(in))
}

func ToUint16[T constraints.Integer](in T) (out uint16, err error) {
	out = uint16(in)

	if uint64(in) > math.MaxUint16 || in < 0 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToUint16[T constraints.Integer](in T) uint16 {
	return Must(ToUint16(in))
}

func ToInt64[T constraints.Integer](in T) (out int64, err error) {
	out = int64(in)

	if uint64(in) > math.MaxInt64 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToInt64[T constraints.Integer](in T) int64 {
	return Must(ToInt64(in))
}

func ToUint64[T constraints.Integer](in T) (out uint64, err error) {
	out = uint64(in)

	if in < 0 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToUint64[T constraints.Integer](in T) uint64 {
	return Must(ToUint64(in))
}

func ToInt32[T constraints.Integer](in T) (out int32, err error) {
	out = int32(in)

	if uint64(in) > math.MaxInt32 || int64(in) < math.MinInt32 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToInt32[T constraints.Integer](in T) int32 {
	return Must(ToInt32(in))
}

func ToUint32[T constraints.Integer](in T) (out uint32, err error) {
	out = uint32(in)

	if uint64(in) > math.MaxInt32 || in < 0 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToUint32[T constraints.Integer](in T) uint32 {
	return Must(ToUint32(in))
}

func ToInt[T constraints.Integer](in T) (out int, err error) {
	out = int(in)

	if uint64(in) > math.MaxInt || int64(in) < math.MinInt {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToInt[T constraints.Integer](in T) int {
	return Must(ToInt(in))
}

func ToUint[T constraints.Integer](in T) (out uint, err error) {
	out = uint(in)

	if uint64(in) > math.MaxInt || in < 0 {
		err = ErrOutOfBounds
	}

	return out, err
}

func MustToUint[T constraints.Integer](in T) uint {
	return Must(ToUint(in))
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
