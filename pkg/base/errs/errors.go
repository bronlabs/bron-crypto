//go:generate go run codegen/error_functions/main.go
//go:generate go run codegen/known_errors/main.go
//nolint:depguard,wrapcheck // we want to use pkg/errors only here, but nowhere else
package errs

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/exp/constraints"
)

type ErrorType string

type AbortIdentifier interface {
	constraints.Integer | ~string | ~[]byte | ~[32]byte
}

const (
	Argument          ErrorType = "[ARGUMENT_ERROR]"
	Coordinates       ErrorType = "[COORDINATES_ERROR]"
	Count             ErrorType = "[COUNT_ERROR]"
	Curve             ErrorType = "[CURVE_ERROR]"
	DivisionByZero    ErrorType = "[DIVISION_BY_ZERO_ERROR]"
	Duplicate         ErrorType = "[DUPLICATE_ERROR]"
	Hashing           ErrorType = "[HASHING_ERROR]"
	IdentifiableAbort ErrorType = "[ABORT]"
	Identifier        ErrorType = "[IDENTIFIER_ERROR]"
	IsIdentity        ErrorType = "[IS_IDENTITY_ERROR]"
	IsNil             ErrorType = "[IS_NIL_ERROR]"
	IsZero            ErrorType = "[IS_ZERO_ERROR]"
	Length            ErrorType = "[LENGTH_ERROR]"
	Membership        ErrorType = "[MEMBERSHIP_ERROR]"
	Missing           ErrorType = "[MISSING_ERROR]"
	Panic             ErrorType = "[PANIC]"
	RandomSample      ErrorType = "[RANDOM_SAMPLE_ERROR]"
	Range             ErrorType = "[RANGE_ERROR]"
	Round             ErrorType = "[ROUND_ERROR]"
	Serialisation     ErrorType = "[SERIALISATION_ERROR]"
	Size              ErrorType = "[SIZE_ERROR]"
	TotalAbort        ErrorType = "[TOTAL_ABORT]"
	Type              ErrorType = "[TYPE_ERROR]"
	Validation        ErrorType = "[VALIDATION_ERROR]"
	Value             ErrorType = "[VALUE_ERROR]"
	Verification      ErrorType = "[VERIFICATION_ERROR]"

	IsNotNil  ErrorType = "[IS_NOT_NIL_ERROR]"
	IsNotZero ErrorType = "[IS_NOT_ZERO_ERROR]"

	Failed ErrorType = "[FAILED]"
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
