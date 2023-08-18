//nolint:depguard,wrapcheck // we want to use pkg/errors only here, but nowhere else
package errs

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"
)

type ErrorType string

type AbortIdentifier interface {
	~int | ~string | ~[]byte | ~[32]byte
}

const (
	deserializationFailed ErrorType = "[DESERIALIZATION_FAILED]"
	serializationFailed   ErrorType = "[SERIALISATION_FAILED]"
	divisionByZero        ErrorType = "[DIVISION_BY_ZERO]"
	duplicate             ErrorType = "[DUPLICATE]"
	failed                ErrorType = "[FAILED]"
	identifiableAbort     ErrorType = "[ABORT]"
	totalAbort            ErrorType = "[TOTAL_ABORT]"
	incorrectCount        ErrorType = "[INCORRECT_COUNT]"
	invalidArgument       ErrorType = "[INVALID_ARGUMENT]"
	invalidCoordinates    ErrorType = "[INVALID_COORDINATES]"
	invalidCurve          ErrorType = "[INVALID_CURVE]"
	invalidIdentifier     ErrorType = "[INVALID_IDENTIFIER]"
	invalidLength         ErrorType = "[INVALID_LENGTH]"
	invalidRound          ErrorType = "[INVALID_ROUND]"
	invalidType           ErrorType = "[INVALID_TYPE]"
	isIdentity            ErrorType = "[IS_IDENTITY]"
	isNil                 ErrorType = "[IS_NIL]"
	isZero                ErrorType = "[IS_ZERO]"
	missing               ErrorType = "[MISSING]"
	notOnCurve            ErrorType = "[NOT_ON_CURVE]"
	verificationFailed    ErrorType = "[VERIFICATION_FAILED]"
)

func is(err error, errorType ErrorType) bool {
	return err != nil && strings.Contains(err.Error(), string(errorType))
}

func has(err error, errorType ErrorType) bool {
	if err == nil {
		return false
	}

	for {
		if is(err, errorType) {
			return true
		}

		cause := errors.Cause(err)
		if errors.Is(cause, err) || cause == nil {
			break
		}
		err = cause
	}

	return false
}

func NewIsNil(format string, args ...any) error {
	return errors.Errorf("%s %s", isNil, fmt.Sprintf(format, args...))
}

func WrapIsNil(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", isNil, fmt.Sprintf(format, args...))
}

func IsIsNil(err error) bool {
	return is(err, isNil)
}

func HasIsNil(err error) bool {
	return has(err, isNil)
}

func NewInvalidArgument(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidArgument, fmt.Sprintf(format, args...))
}

func WrapInvalidArgument(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidArgument, fmt.Sprintf(format, args...))
}

func IsInvalidArgument(err error) bool {
	return is(err, invalidArgument)
}

func HasInvalidArgument(err error) bool {
	return has(err, invalidArgument)
}

func NewNotOnCurve(format string, args ...any) error {
	return errors.Errorf("%s %s", notOnCurve, fmt.Sprintf(format, args...))
}

func WrapNotOnCurve(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", notOnCurve, fmt.Sprintf(format, args...))
}

func IsNotOnCurve(err error) bool {
	return is(err, notOnCurve)
}

func HasNotOnCurve(err error) bool {
	return has(err, notOnCurve)
}

func NewInvalidCoordinates(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidCoordinates, fmt.Sprintf(format, args...))
}

func WrapInvalidCoordinates(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidCoordinates, fmt.Sprintf(format, args...))
}

func IsInvalidCoordinates(err error) bool {
	return is(err, invalidCoordinates)
}

func HasInvalidCoordinates(err error) bool {
	return has(err, invalidCoordinates)
}

func NewInvalidCurve(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidCurve, fmt.Sprintf(format, args...))
}

func WrapInvalidCurve(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidCurve, fmt.Sprintf(format, args...))
}

func IsInvalidCurve(err error) bool {
	return is(err, invalidCurve)
}

func HasInvalidCurve(err error) bool {
	return has(err, invalidCurve)
}

func NewIsZero(format string, args ...any) error {
	return errors.Errorf("%s %s", isZero, fmt.Sprintf(format, args...))
}

func WrapIsZero(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", isZero, fmt.Sprintf(format, args...))
}

func IsIsZero(err error) bool {
	return is(err, isZero)
}

func HasIsZero(err error) bool {
	return has(err, isZero)
}

func NewIsIdentity(format string, args ...any) error {
	return errors.Errorf("%s %s", isIdentity, fmt.Sprintf(format, args...))
}

func WrapIsIdentity(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", isIdentity, fmt.Sprintf(format, args...))
}

func IsIsIdentity(err error) bool {
	return is(err, isIdentity)
}

func HasIsIdentity(err error) bool {
	return has(err, isIdentity)
}

func NewInvalidRound(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidRound, fmt.Sprintf(format, args...))
}

func WrapInvalidRound(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidRound, fmt.Sprintf(format, args...))
}

func IsInvalidRound(err error) bool {
	return is(err, invalidRound)
}

func HasInvalidRound(err error) bool {
	return has(err, invalidRound)
}

func NewInvalidType(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidType, fmt.Sprintf(format, args...))
}

func WrapInvalidType(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidType, fmt.Sprintf(format, args...))
}

func IsInvalidType(err error) bool {
	return is(err, invalidType)
}

func HasInvalidType(err error) bool {
	return has(err, invalidType)
}

func NewIncorrectCount(format string, args ...any) error {
	return errors.Errorf("%s %s", incorrectCount, fmt.Sprintf(format, args...))
}

func WrapIncorrectCount(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", incorrectCount, fmt.Sprintf(format, args...))
}

func IsIncorrectCount(err error) bool {
	return is(err, incorrectCount)
}

func HasIncorrectCount(err error) bool {
	return has(err, incorrectCount)
}

func NewVerificationFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", verificationFailed, fmt.Sprintf(format, args...))
}

func WrapVerificationFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", verificationFailed, fmt.Sprintf(format, args...))
}

func IsVerificationFailed(err error) bool {
	return is(err, verificationFailed)
}

func HasVerificationFailed(err error) bool {
	return has(err, verificationFailed)
}

func NewDivisionByZero(format string, args ...any) error {
	return errors.Errorf("%s %s", divisionByZero, fmt.Sprintf(format, args...))
}

func WrapDivisionByZero(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", divisionByZero, fmt.Sprintf(format, args...))
}

func IsDivisionByZero(err error) bool {
	return is(err, divisionByZero)
}

func HasDivisionByZero(err error) bool {
	return has(err, divisionByZero)
}

func NewInvalidLength(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidLength, fmt.Sprintf(format, args...))
}

func WrapInvalidLength(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidLength, fmt.Sprintf(format, args...))
}

func IsInvalidLength(err error) bool {
	return is(err, invalidLength)
}

func HasInvalidLength(err error) bool {
	return has(err, invalidLength)
}

func NewInvalidIdentifier(format string, args ...any) error {
	return errors.Errorf("%s %s", invalidIdentifier, fmt.Sprintf(format, args...))
}

func WrapInvalidIdentifier(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", invalidIdentifier, fmt.Sprintf(format, args...))
}

func IsInvalidIdentifier(err error) bool {
	return is(err, invalidIdentifier)
}

func HasInvalidIdentifier(err error) bool {
	return has(err, invalidIdentifier)
}

func NewDeserializationFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", deserializationFailed, fmt.Sprintf(format, args...))
}

func WrapDeserializationFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", deserializationFailed, fmt.Sprintf(format, args...))
}

func IsDeserializationFailed(err error) bool {
	return is(err, deserializationFailed)
}

func HasDeserializationFailed(err error) bool {
	return has(err, deserializationFailed)
}

func NewSerializationFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", serializationFailed, fmt.Sprintf(format, args...))
}

func WrapSerializationFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", serializationFailed, fmt.Sprintf(format, args...))
}

func IsSerializationFailed(err error) bool {
	return is(err, serializationFailed)
}

func HasSerializationFailed(err error) bool {
	return has(err, serializationFailed)
}

func NewMissing(format string, args ...any) error {
	return errors.Errorf("%s %s", missing, fmt.Sprintf(format, args...))
}

func WrapMissing(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", missing, fmt.Sprintf(format, args...))
}

func IsMissing(err error) bool {
	return is(err, missing)
}

func HasMissing(err error) bool {
	return has(err, missing)
}

func NewDuplicate(format string, args ...any) error {
	return errors.Errorf("%s %s", duplicate, fmt.Sprintf(format, args...))
}

func WrapDuplicate(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", duplicate, fmt.Sprintf(format, args...))
}

func IsDuplicate(err error) bool {
	return is(err, duplicate)
}

func HasDuplicate(err error) bool {
	return has(err, duplicate)
}

func NewIdentifiableAbort[T AbortIdentifier](id T, format string, args ...any) error {
	return errors.Errorf(
		"%s(ID=%s) %s",
		identifiableAbort,
		fmt.Sprintf(abortFormatSpecifier(id), id),
		fmt.Sprintf(format, args...),
	)
}

func WrapIdentifiableAbort[T AbortIdentifier](err error, id T, format string, args ...any) error {
	return errors.Wrapf(
		err,
		"%s(ID=%s) %s",
		identifiableAbort,
		fmt.Sprintf(abortFormatSpecifier(id), id),
		fmt.Sprintf(format, args...),
	)
}

func IsIdentifiableAbort(err error, id any) bool {
	t := identifiableAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return is(err, t)
}

func HasIdentifiableAbort(err error, id any) bool {
	t := identifiableAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return has(err, t)
}

func NewTotalAbort(id any, format string, args ...any) error {
	if id != nil {
		return errors.Errorf(
			"%s(ID=%s) %s",
			totalAbort,
			fmt.Sprintf(abortFormatSpecifier(id), id),
			fmt.Sprintf(format, args...),
		)
	}
	return errors.Errorf("%s %s", identifiableAbort, fmt.Sprintf(format, args...))
}

func WrapTotalAbort(err error, id any, format string, args ...any) error {
	if id != nil {
		return errors.Wrapf(
			err,
			"%s(ID=%s) %s",
			totalAbort,
			fmt.Sprintf(abortFormatSpecifier(id), id),
			fmt.Sprintf(format, args...),
		)
	}
	return errors.Wrapf(err, "%s %s", identifiableAbort, fmt.Sprintf(format, args...))
}

func IsTotalAbort(err error, id any) bool {
	t := totalAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return is(err, t)
}

func HasTotalAbort(err error, id any) bool {
	t := identifiableAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return has(err, t)
}

func NewFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", failed, fmt.Sprintf(format, args...))
}

func WrapFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", failed, fmt.Sprintf(format, args...))
}

func IsFailed(err error) bool {
	return is(err, failed)
}

func HasFailed(err error) bool {
	return has(err, failed)
}

func isByteArrayOrSlice(x any) bool {
	if _, ok := x.([]byte); ok {
		return true
	}
	v := reflect.ValueOf(x)
	return v.Kind() == reflect.Array && v.Type().Elem().Kind() == reflect.Uint8
}

func abortFormatSpecifier(id any) string {
	specifier := "%v"
	if isByteArrayOrSlice(id) {
		specifier = "%x"
	}
	return specifier
}
