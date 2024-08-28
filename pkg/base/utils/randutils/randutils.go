package randutils

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"reflect"

	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const (
	AlphaNumericCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	HexCharSet          = "0123456789ABCDEF"
)

func IsSigned[T constraints.Integer](x T) bool {
	switch reflect.TypeOf(x).Kind() { //nolint:exhaustive // intentional,for readability.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

func RandomBigInt(prng io.Reader, minInt, maxInt *big.Int, nonZero bool) (*big.Int, error) {
	if err := validateRandomBigInt(prng, minInt, maxInt, nonZero); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	rangeSize := new(big.Int).Add(new(big.Int).Sub(maxInt, minInt), big.NewInt(1))
	for {
		n, err := crand.Int(prng, rangeSize)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample random big int")
		}
		n = new(big.Int).Add(n, minInt)
		if nonZero && n.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		return n, nil
	}
}

func validateRandomBigInt(prng io.Reader, minInt, maxInt *big.Int, nonZero bool) error {
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if maxInt == nil {
		return errs.NewIsNil("max")
	}
	if minInt == nil {
		return errs.NewIsNil("min")
	}
	if maxInt.Cmp(minInt) == -1 {
		return errs.NewValue("max must not be less than min")
	}
	rangeSize := new(big.Int).Add(new(big.Int).Sub(maxInt, minInt), big.NewInt(1))
	if nonZero && rangeSize.Cmp(big.NewInt(0)) == 0 {
		return errs.NewSize("max - min == 0 && nonZero output is required")
	}
	return nil
}

func RandomInteger[T constraints.Integer](prng io.Reader, minInt, maxInt T, nonZero bool) (T, error) {
	if err := validateRandomInt(prng, minInt, maxInt, nonZero); err != nil {
		return 0, errs.WrapArgument(err, "invalid argument")
	}
	signedT := IsSigned(minInt)
	var maxBig *big.Int
	var minBig *big.Int
	if signedT {
		maxBig = new(big.Int).SetInt64(int64(maxInt))
		minBig = new(big.Int).SetInt64(int64(minInt))
	} else {
		maxBig = new(big.Int).SetUint64(uint64(maxInt))
		minBig = new(big.Int).SetUint64(uint64(minInt))
	}
	n, err := RandomBigInt(prng, minBig, maxBig, nonZero)
	if err != nil {
		return 0, errs.WrapRandomSample(err, "samplig big int failed")
	}
	if signedT {
		return T(n.Int64()), nil
	}
	return T(n.Uint64()), nil
}

func validateRandomInt[T constraints.Integer](prng io.Reader, minInt, maxInt T, nonZero bool) error {
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if maxInt < minInt {
		return errs.NewValue("max must not be less than min")
	}
	if nonZero && maxInt-minInt == 0 {
		return errs.NewValue("max - min == 0 && nonZero output is required")
	}
	return nil
}

func RandomString[T ~string](prng io.Reader, charset string, minLen, maxLen int, distinct bool) (T, error) {
	if err := validateRandomString(prng, charset, minLen, maxLen, distinct); err != nil {
		return "", errs.WrapArgument(err, "could not validate arguments")
	}
	if charset == "" {
		return "", nil
	}
	effectiveCharSet, err := combinatorics.Shuffle([]rune(charset), prng)
	if err != nil {
		return "", errs.WrapFailed(err, "could not shuffle charset")
	}

	sliceLength, err := RandomInteger(prng, minLen, maxLen, false)
	if err != nil {
		return T(""), errs.WrapRandomSample(err, "could not sample slice length size")
	}
	if sliceLength == len(effectiveCharSet) {
		return T(string(effectiveCharSet)), nil
	}
	randomRunes, err := RandomSlice[[]rune, rune](prng, sliceLength, distinct, false, func() (rune, error) {
		index, err := crand.Int(prng, big.NewInt(int64(len(effectiveCharSet))))
		if err != nil {
			return 0, errs.WrapRandomSample(err, "could not sample from charset")
		}
		return effectiveCharSet[index.Int64()], nil
	})
	if err != nil {
		return T(""), errs.WrapRandomSample(err, "could not sample random rune slice")
	}
	return T(string(randomRunes)), nil
}

func validateRandomString(prng io.Reader, charset string, minLen, maxLen int, distinct bool) error {
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if minLen < 0 {
		return errs.NewValue("minimum length can't be negative")
	}
	if maxLen < minLen {
		return errs.NewValue("max must not be less than min")
	}
	if (maxLen-minLen) > len(charset) && distinct {
		return errs.NewValue("can't generate distinct strings with provided ranges")
	}
	return nil
}

func RandomAlphaNumericString[T ~string](prng io.Reader, minLen, maxLen int, distinct bool) (T, error) {
	return RandomString[T](prng, AlphaNumericCharSet, minLen, maxLen, distinct)
}

func RandomHex[T ~string](prng io.Reader, minLen, maxLen int, distinct bool) (T, error) {
	return RandomString[T](prng, HexCharSet, minLen, maxLen, distinct)
}

func RandomBool[T ~bool](prng io.Reader) (T, error) {
	n, err := RandomInteger(prng, 0, 1, false)
	if err != nil {
		return false, errs.WrapRandomSample(err, "could not sample either 0 or 1")
	}
	return T(n == 1), nil
}

func RandomByte[T ~byte](prng io.Reader, nonZero bool) (T, error) {
	for {
		n, err := RandomInteger[uint8](prng, 0, 7, false)
		if err != nil {
			return T(0), errs.WrapRandomSample(err, "could not sample either 0 or 1")
		}
		if nonZero && n == 0 {
			continue
		}
		return T(n), nil
	}
}

func RandomSlice[S ~[]T, T comparable](prng io.Reader, sliceLength int, distinct, notAllZero bool, sampler func() (T, error)) (S, error) {
	zeroValue := reflect.Zero(reflect.ValueOf(new(T)).Type())
SAMPLER:
	for {
		out := make(S, sliceLength)
		seen := map[T]any{}
		for i := range sliceLength {
			for {
				current, err := sampler()
				if err != nil {
					return nil, errs.WrapRandomSample(err, "could not sample at index %d", i)
				}
				if _, exists := seen[current]; distinct && exists {
					continue
				}
				out[i] = current
				seen[current] = true
				break
			}
		}
		if notAllZero {
			for _, x := range out {
				if reflect.ValueOf(x).Interface() == zeroValue.Interface() {
					continue SAMPLER
				}
			}
		}
		return out, nil
	}
}

func RandomSliceOfIntegers[S ~[]T, T constraints.Integer](prng io.Reader, minSliceLength, maxSliceLength int, minInteger, maxInteger T, distinct, notAllZero, notAnyZero bool) (S, error) {
	if err := validateRandomSliceOfIntegers(prng, minSliceLength, maxSliceLength, minInteger, maxInteger, distinct, notAnyZero); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	sliceLength, err := RandomInteger(prng, minSliceLength, maxSliceLength, false)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample slice length")
	}
	out, err := RandomSlice[S, T](prng, sliceLength, distinct, notAllZero, func() (T, error) {
		return RandomInteger(prng, minInteger, maxInteger, notAnyZero)
	})
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample an empty slice")
	}
	return out, nil
}

func validateRandomSliceOfIntegers[T constraints.Integer](prng io.Reader, minSlice, maxSlice int, minInteger, maxInteger T, distinct, nonZero bool) error {
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if minSlice < 0 {
		return errs.NewValue("min slice length < 0")
	}
	if maxSlice < 0 {
		return errs.NewValue("max slice length < 0")
	}
	if maxSlice < minSlice {
		return errs.NewValue("max slice length < min slice length")
	}
	if maxInteger < minInteger {
		return errs.NewValue("max integer < min integer")
	}
	totalIntegers := maxInteger - minInteger + 1
	if nonZero && minInteger < 0 && maxInteger >= 0 {
		totalIntegers--
	}
	if distinct {
		if minSlice > int(totalIntegers) {
			return errs.NewValue("sample with minimum size will need more ints than given to have all distinct elements")
		}
	}
	return nil
}

func RandomSliceOfBytes[S ~[]T, T ~byte](prng io.Reader, minSliceLength, maxSliceLength int, nonEmpty, notAllZero, notAnyZero bool) (S, error) {
	sliceLength, err := RandomInteger(prng, minSliceLength, maxSliceLength, false)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample slice length")
	}
	out, err := RandomSlice[S, T](prng, sliceLength, false, notAllZero, func() (T, error) {
		return RandomByte[T](prng, notAnyZero)
	})
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample an empty slice")
	}
	return out, nil
}
