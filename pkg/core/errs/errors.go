package errs

import (
	"fmt"
	"github.com/pkg/errors"
)

type ErrorType string

const (
	isNil                 ErrorType = "[IS_NIL]"
	invalidArgument       ErrorType = "[INVALID_ARGUMENT]"
	notOnCurve            ErrorType = "[NOT_ON_CURVE]"
	invalidCurve          ErrorType = "[INVALID_CURVE]"
	isZero                ErrorType = "[IS_ZERO]"
	isIdentity            ErrorType = "[IS_IDENTITY]"
	invalidRound          ErrorType = "[INVALID_ROUND]"
	incorrectCount        ErrorType = "[INCORRECT_COUNT]"
	verificationFailed    ErrorType = "[VERIFICATION_FAILED]"
	divisionByZero        ErrorType = "[DIVISION_BY_ZERO]"
	invalidIdentifier     ErrorType = "[INVALID_IDENTIFIER]"
	deserializationFailed ErrorType = "[DESERIALIZATION_FAILED]"
	missing               ErrorType = "[MISSING]"
	duplicate             ErrorType = "[DUPLICATE]"
	identifiableAbort     ErrorType = "[ABORT]"
	failed                ErrorType = "[FAILED]"
)

func NewIsNil(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", isNil, fmt.Sprintf(format, args...))
}

func WrapIsNil(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", isNil, fmt.Sprintf(format, args...))
}

func NewInvalidArgument(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", invalidArgument, fmt.Sprintf(format, args...))
}

func WrapInvalidArgument(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", invalidArgument, fmt.Sprintf(format, args...))
}

func NewNotOnCurve(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", notOnCurve, fmt.Sprintf(format, args...))
}

func WrapNotOnCurve(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", notOnCurve, fmt.Sprintf(format, args...))
}

func NewInvalidCurve(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", invalidCurve, fmt.Sprintf(format, args...))
}

func WrapInvalidCurve(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", invalidCurve, fmt.Sprintf(format, args...))
}

func NewIsZero(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", isZero, fmt.Sprintf(format, args...))
}

func WrapIsZero(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", isZero, fmt.Sprintf(format, args...))
}

func NewIsIdentity(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", isIdentity, fmt.Sprintf(format, args...))
}

func WrapIsIdentity(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", isIdentity, fmt.Sprintf(format, args...))
}

func NewInvalidRound(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", invalidRound, fmt.Sprintf(format, args...))
}

func WrapInvalidRound(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", invalidRound, fmt.Sprintf(format, args...))
}

func NewIncorrectCount(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", incorrectCount, fmt.Sprintf(format, args...))
}

func WrapIncorrectCount(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", incorrectCount, fmt.Sprintf(format, args...))
}

func NewVerificationFailed(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", verificationFailed, fmt.Sprintf(format, args...))
}

func WrapVerificationFailed(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", verificationFailed, fmt.Sprintf(format, args...))
}

func NewDivisionByZero(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", divisionByZero, fmt.Sprintf(format, args...))
}

func WrapDivisionByZero(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", divisionByZero, fmt.Sprintf(format, args...))
}

func NewInvalidIdentifier(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", invalidIdentifier, fmt.Sprintf(format, args...))
}

func WrapInvalidIdentifier(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", invalidIdentifier, fmt.Sprintf(format, args...))
}

func NewDeserializationFailed(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", deserializationFailed, fmt.Sprintf(format, args...))
}

func WrapDeserializationFailed(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", deserializationFailed, fmt.Sprintf(format, args...))
}

func NewMissing(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", missing, fmt.Sprintf(format, args...))
}

func WrapMissing(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", missing, fmt.Sprintf(format, args...))
}

func NewDuplicate(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", duplicate, fmt.Sprintf(format, args...))
}

func WrapDuplicate(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", duplicate, fmt.Sprintf(format, args...))
}

func NewIdentifiableAbort(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", identifiableAbort, fmt.Sprintf(format, args...))
}

func WrapIdentifiableAbort(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", identifiableAbort, fmt.Sprintf(format, args...))
}

func NewFailed(format string, args ...interface{}) error {
	return errors.Errorf("%s %s", failed, fmt.Sprintf(format, args...))
}

func WrapFailed(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, "%s %s", failed, fmt.Sprintf(format, args...))
}
