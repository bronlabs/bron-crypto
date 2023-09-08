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
	DivisionByZero     ErrorType = "[DIVISION_BY_ZERO]"
	Duplicate          ErrorType = "[DUPLICATE]"
	Failed             ErrorType = "[FAILED]"
	IdentifiableAbort  ErrorType = "[ABORT]"
	IncorrectCount     ErrorType = "[INCORRECT_COUNT]"
	InvalidArgument    ErrorType = "[INVALID_ARGUMENT]"
	InvalidCoordinates ErrorType = "[INVALID_COORDINATES]"
	InvalidCurve       ErrorType = "[INVALID_CURVE]"
	InvalidIdentifier  ErrorType = "[INVALID_IDENTIFIER]"
	InvalidLength      ErrorType = "[INVALID_LENGTH]"
	InvalidRange       ErrorType = "[INVALID_RANGE]"
	InvalidRound       ErrorType = "[INVALID_ROUND]"
	InvalidType        ErrorType = "[INVALID_TYPE]"
	IsIdentity         ErrorType = "[IS_IDENTITY]"
	IsNil              ErrorType = "[IS_NIL]"
	IsZero             ErrorType = "[IS_ZERO]"
	Membership         ErrorType = "[MEMBERSHIP]"
	Missing            ErrorType = "[MISSING]"
	Serialisation      ErrorType = "[SERIALISATION_ERROR]"
	RandomSampleFailed ErrorType = "[RANDOM_SAMPLE_FAILED]"
	TotalAbort         ErrorType = "[TOTAL_ABORT]"
	VerificationFailed ErrorType = "[VERIFICATION_FAILED]"
)

var knownErrors = []ErrorType{
	DivisionByZero,
	Duplicate,
	Failed,
	IdentifiableAbort,
	IncorrectCount,
	InvalidArgument,
	InvalidCoordinates,
	InvalidCurve,
	InvalidIdentifier,
	InvalidLength,
	InvalidRound,
	InvalidType,
	IsIdentity,
	IsNil,
	IsZero,
	Membership,
	Missing,
	Serialisation,
	RandomSampleFailed,
	TotalAbort,
	VerificationFailed,
}

func Is(err error, errorType ErrorType) bool {
	return err != nil && strings.Contains(err.Error(), string(errorType))
}

func Has(err error, errorType ErrorType) bool {
	if err == nil {
		return false
	}

	for {
		if Is(err, errorType) {
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
	return errors.Errorf("%s %s", IsNil, fmt.Sprintf(format, args...))
}

func WrapIsNil(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", IsNil, fmt.Sprintf(format, args...))
}

func IsIsNil(err error) bool {
	return Is(err, IsNil)
}

func HasIsNil(err error) bool {
	return Has(err, IsNil)
}

func NewInvalidArgument(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidArgument, fmt.Sprintf(format, args...))
}

func WrapInvalidArgument(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidArgument, fmt.Sprintf(format, args...))
}

func IsInvalidArgument(err error) bool {
	return Is(err, InvalidArgument)
}

func HasInvalidArgument(err error) bool {
	return Has(err, InvalidArgument)
}

func NewMembershipError(format string, args ...any) error {
	return errors.Errorf("%s %s", Membership, fmt.Sprintf(format, args...))
}

func WrapMembershipError(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Membership, fmt.Sprintf(format, args...))
}

func IsMembershipError(err error) bool {
	return Is(err, Membership)
}

func HasMembershipError(err error) bool {
	return Has(err, Membership)
}

func NewInvalidCoordinates(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidCoordinates, fmt.Sprintf(format, args...))
}

func WrapInvalidCoordinates(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidCoordinates, fmt.Sprintf(format, args...))
}

func IsInvalidCoordinates(err error) bool {
	return Is(err, InvalidCoordinates)
}

func HasInvalidCoordinates(err error) bool {
	return Has(err, InvalidCoordinates)
}

func NewInvalidCurve(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidCurve, fmt.Sprintf(format, args...))
}

func WrapInvalidCurve(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidCurve, fmt.Sprintf(format, args...))
}

func IsInvalidCurve(err error) bool {
	return Is(err, InvalidCurve)
}

func HasInvalidCurve(err error) bool {
	return Has(err, InvalidCurve)
}

func NewIsZero(format string, args ...any) error {
	return errors.Errorf("%s %s", IsZero, fmt.Sprintf(format, args...))
}

func WrapIsZero(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", IsZero, fmt.Sprintf(format, args...))
}

func IsIsZero(err error) bool {
	return Is(err, IsZero)
}

func HasIsZero(err error) bool {
	return Has(err, IsZero)
}

func NewIsIdentity(format string, args ...any) error {
	return errors.Errorf("%s %s", IsIdentity, fmt.Sprintf(format, args...))
}

func WrapIsIdentity(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", IsIdentity, fmt.Sprintf(format, args...))
}

func IsIsIdentity(err error) bool {
	return Is(err, IsIdentity)
}

func HasIsIdentity(err error) bool {
	return Has(err, IsIdentity)
}

func NewInvalidRange(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidRange, fmt.Sprintf(format, args...))
}

func WrapInvalidRange(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidRange, fmt.Sprintf(format, args...))
}

func IsInvalidRange(err error) bool {
	return Is(err, InvalidRange)
}

func HasInvalidRange(err error) bool {
	return Has(err, InvalidRange)
}

func NewInvalidRound(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidRound, fmt.Sprintf(format, args...))
}

func WrapInvalidRound(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidRound, fmt.Sprintf(format, args...))
}

func IsInvalidRound(err error) bool {
	return Is(err, InvalidRound)
}

func HasInvalidRound(err error) bool {
	return Has(err, InvalidRound)
}

func NewInvalidType(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidType, fmt.Sprintf(format, args...))
}

func WrapInvalidType(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidType, fmt.Sprintf(format, args...))
}

func IsInvalidType(err error) bool {
	return Is(err, InvalidType)
}

func HasInvalidType(err error) bool {
	return Has(err, InvalidType)
}

func NewIncorrectCount(format string, args ...any) error {
	return errors.Errorf("%s %s", IncorrectCount, fmt.Sprintf(format, args...))
}

func WrapIncorrectCount(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", IncorrectCount, fmt.Sprintf(format, args...))
}

func IsIncorrectCount(err error) bool {
	return Is(err, IncorrectCount)
}

func HasIncorrectCount(err error) bool {
	return Has(err, IncorrectCount)
}

func NewVerificationFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", VerificationFailed, fmt.Sprintf(format, args...))
}

func WrapVerificationFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", VerificationFailed, fmt.Sprintf(format, args...))
}

func IsVerificationFailed(err error) bool {
	return Is(err, VerificationFailed)
}

func HasVerificationFailed(err error) bool {
	return Has(err, VerificationFailed)
}

func NewDivisionByZero(format string, args ...any) error {
	return errors.Errorf("%s %s", DivisionByZero, fmt.Sprintf(format, args...))
}

func WrapDivisionByZero(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", DivisionByZero, fmt.Sprintf(format, args...))
}

func IsDivisionByZero(err error) bool {
	return Is(err, DivisionByZero)
}

func HasDivisionByZero(err error) bool {
	return Has(err, DivisionByZero)
}

func NewInvalidLength(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidLength, fmt.Sprintf(format, args...))
}

func WrapInvalidLength(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidLength, fmt.Sprintf(format, args...))
}

func IsInvalidLength(err error) bool {
	return Is(err, InvalidLength)
}

func HasInvalidLength(err error) bool {
	return Has(err, InvalidLength)
}

func NewRandomSampleFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", RandomSampleFailed, fmt.Sprintf(format, args...))
}

func WrapRandomSampleFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", RandomSampleFailed, fmt.Sprintf(format, args...))
}

func IsRandomSampleFailed(err error) bool {
	return Is(err, RandomSampleFailed)
}

func HasRandomSampleFailed(err error) bool {
	return Has(err, RandomSampleFailed)
}

func NewInvalidIdentifier(format string, args ...any) error {
	return errors.Errorf("%s %s", InvalidIdentifier, fmt.Sprintf(format, args...))
}

func WrapInvalidIdentifier(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", InvalidIdentifier, fmt.Sprintf(format, args...))
}

func IsInvalidIdentifier(err error) bool {
	return Is(err, InvalidIdentifier)
}

func HasInvalidIdentifier(err error) bool {
	return Has(err, InvalidIdentifier)
}

func NewSerializationError(format string, args ...any) error {
	return errors.Errorf("%s %s", Serialisation, fmt.Sprintf(format, args...))
}

func WrapSerializationError(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Serialisation, fmt.Sprintf(format, args...))
}

func IsSerializationError(err error) bool {
	return Is(err, Serialisation)
}

func HasSerializationError(err error) bool {
	return Has(err, Serialisation)
}

func NewMissing(format string, args ...any) error {
	return errors.Errorf("%s %s", Missing, fmt.Sprintf(format, args...))
}

func WrapMissing(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Missing, fmt.Sprintf(format, args...))
}

func IsMissing(err error) bool {
	return Is(err, Missing)
}

func HasMissing(err error) bool {
	return Has(err, Missing)
}

func NewDuplicate(format string, args ...any) error {
	return errors.Errorf("%s %s", Duplicate, fmt.Sprintf(format, args...))
}

func WrapDuplicate(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Duplicate, fmt.Sprintf(format, args...))
}

func IsDuplicate(err error) bool {
	return Is(err, Duplicate)
}

func HasDuplicate(err error) bool {
	return Has(err, Duplicate)
}

func NewIdentifiableAbort[T AbortIdentifier](id T, format string, args ...any) error {
	return errors.Errorf(
		"%s(ID=%s) %s",
		IdentifiableAbort,
		fmt.Sprintf(abortFormatSpecifier(id), id),
		fmt.Sprintf(format, args...),
	)
}

func WrapIdentifiableAbort[T AbortIdentifier](err error, id T, format string, args ...any) error {
	return errors.Wrapf(
		err,
		"%s(ID=%s) %s",
		IdentifiableAbort,
		fmt.Sprintf(abortFormatSpecifier(id), id),
		fmt.Sprintf(format, args...),
	)
}

func IsIdentifiableAbort(err error, id any) bool {
	t := IdentifiableAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return Is(err, t)
}

func HasIdentifiableAbort(err error, id any) bool {
	t := IdentifiableAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return Has(err, t)
}

func NewTotalAbort(id any, format string, args ...any) error {
	if id != nil {
		return errors.Errorf(
			"%s(ID=%s) %s",
			TotalAbort,
			fmt.Sprintf(abortFormatSpecifier(id), id),
			fmt.Sprintf(format, args...),
		)
	}
	return errors.Errorf("%s %s", IdentifiableAbort, fmt.Sprintf(format, args...))
}

func WrapTotalAbort(err error, id any, format string, args ...any) error {
	if id != nil {
		return errors.Wrapf(
			err,
			"%s(ID=%s) %s",
			TotalAbort,
			fmt.Sprintf(abortFormatSpecifier(id), id),
			fmt.Sprintf(format, args...),
		)
	}
	return errors.Wrapf(err, "%s %s", IdentifiableAbort, fmt.Sprintf(format, args...))
}

func IsTotalAbort(err error, id any) bool {
	t := TotalAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return Is(err, t)
}

func HasTotalAbort(err error, id any) bool {
	t := IdentifiableAbort
	if id != nil {
		t = ErrorType(
			fmt.Sprintf(
				"%s(ID=%s)", t, fmt.Sprintf(abortFormatSpecifier(id), id),
			),
		)
	}
	return Has(err, t)
}

func NewFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", Failed, fmt.Sprintf(format, args...))
}

func WrapFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Failed, fmt.Sprintf(format, args...))
}

func IsFailed(err error) bool {
	return Is(err, Failed)
}

func HasFailed(err error) bool {
	return Has(err, Failed)
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

// IsKnownError returns true if the error is one of the known errors.
func IsKnownError(err error) bool {
	if err == nil {
		return false
	}
	for _, knownError := range knownErrors {
		if Is(err, knownError) {
			return true
		}
	}
	return false
}
