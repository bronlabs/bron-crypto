//go:generate go run codegen/error_functions/main.go
//go:generate go run codegen/known_errors/main.go
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
	HashingFailed      ErrorType = "[HASHING_FAILED]"
	TotalAbort         ErrorType = "[TOTAL_ABORT]"
	VerificationFailed ErrorType = "[VERIFICATION_FAILED]"
)

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
