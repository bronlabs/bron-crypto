//nolint:depguard,wrapcheck // we want to use pkg/errors only here, but nowhere else
package errs

import (
	"fmt"

	"github.com/pkg/errors"
)

func NewArgument(format string, args ...any) error {
	return errors.Errorf("%s %s", Argument, fmt.Sprintf(format, args...))
}

func WrapArgument(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Argument, fmt.Sprintf(format, args...))
}

func IsArgument(err error) bool {
	return Is(err, Argument)
}

func HasArgument(err error) bool {
	return Has(err, Argument)
}

func NewCoordinates(format string, args ...any) error {
	return errors.Errorf("%s %s", Coordinates, fmt.Sprintf(format, args...))
}

func WrapCoordinates(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Coordinates, fmt.Sprintf(format, args...))
}

func IsCoordinates(err error) bool {
	return Is(err, Coordinates)
}

func HasCoordinates(err error) bool {
	return Has(err, Coordinates)
}

func NewCurve(format string, args ...any) error {
	return errors.Errorf("%s %s", Curve, fmt.Sprintf(format, args...))
}

func WrapCurve(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Curve, fmt.Sprintf(format, args...))
}

func IsCurve(err error) bool {
	return Is(err, Curve)
}

func HasCurve(err error) bool {
	return Has(err, Curve)
}

func NewHashing(format string, args ...any) error {
	return errors.Errorf("%s %s", Hashing, fmt.Sprintf(format, args...))
}

func WrapHashing(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Hashing, fmt.Sprintf(format, args...))
}

func IsHashing(err error) bool {
	return Is(err, Hashing)
}

func HasHashing(err error) bool {
	return Has(err, Hashing)
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

func NewLength(format string, args ...any) error {
	return errors.Errorf("%s %s", Length, fmt.Sprintf(format, args...))
}

func WrapLength(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Length, fmt.Sprintf(format, args...))
}

func IsLength(err error) bool {
	return Is(err, Length)
}

func HasLength(err error) bool {
	return Has(err, Length)
}

func NewMembership(format string, args ...any) error {
	return errors.Errorf("%s %s", Membership, fmt.Sprintf(format, args...))
}

func WrapMembership(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Membership, fmt.Sprintf(format, args...))
}

func IsMembership(err error) bool {
	return Is(err, Membership)
}

func HasMembership(err error) bool {
	return Has(err, Membership)
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

func NewRandomSample(format string, args ...any) error {
	return errors.Errorf("%s %s", RandomSample, fmt.Sprintf(format, args...))
}

func WrapRandomSample(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", RandomSample, fmt.Sprintf(format, args...))
}

func IsRandomSample(err error) bool {
	return Is(err, RandomSample)
}

func HasRandomSample(err error) bool {
	return Has(err, RandomSample)
}

func NewRound(format string, args ...any) error {
	return errors.Errorf("%s %s", Round, fmt.Sprintf(format, args...))
}

func WrapRound(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Round, fmt.Sprintf(format, args...))
}

func IsRound(err error) bool {
	return Is(err, Round)
}

func HasRound(err error) bool {
	return Has(err, Round)
}

func NewSerialisation(format string, args ...any) error {
	return errors.Errorf("%s %s", Serialisation, fmt.Sprintf(format, args...))
}

func WrapSerialisation(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Serialisation, fmt.Sprintf(format, args...))
}

func IsSerialisation(err error) bool {
	return Is(err, Serialisation)
}

func HasSerialisation(err error) bool {
	return Has(err, Serialisation)
}

func NewSize(format string, args ...any) error {
	return errors.Errorf("%s %s", Size, fmt.Sprintf(format, args...))
}

func WrapSize(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Size, fmt.Sprintf(format, args...))
}

func IsSize(err error) bool {
	return Is(err, Size)
}

func HasSize(err error) bool {
	return Has(err, Size)
}

func NewType(format string, args ...any) error {
	return errors.Errorf("%s %s", Type, fmt.Sprintf(format, args...))
}

func WrapType(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Type, fmt.Sprintf(format, args...))
}

func IsType(err error) bool {
	return Is(err, Type)
}

func HasType(err error) bool {
	return Has(err, Type)
}

func NewValidation(format string, args ...any) error {
	return errors.Errorf("%s %s", Validation, fmt.Sprintf(format, args...))
}

func WrapValidation(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Validation, fmt.Sprintf(format, args...))
}

func IsValidation(err error) bool {
	return Is(err, Validation)
}

func HasValidation(err error) bool {
	return Has(err, Validation)
}

func NewValue(format string, args ...any) error {
	return errors.Errorf("%s %s", Value, fmt.Sprintf(format, args...))
}

func WrapValue(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Value, fmt.Sprintf(format, args...))
}

func IsValue(err error) bool {
	return Is(err, Value)
}

func HasValue(err error) bool {
	return Has(err, Value)
}

func NewVerification(format string, args ...any) error {
	return errors.Errorf("%s %s", Verification, fmt.Sprintf(format, args...))
}

func WrapVerification(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", Verification, fmt.Sprintf(format, args...))
}

func IsVerification(err error) bool {
	return Is(err, Verification)
}

func HasVerification(err error) bool {
	return Has(err, Verification)
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
