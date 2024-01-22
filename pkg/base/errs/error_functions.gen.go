//nolint:depguard,wrapcheck // we want to use pkg/errors only here, but nowhere else
package errs

import (
	"fmt"

	"github.com/pkg/errors"
)

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

func NewHashingFailed(format string, args ...any) error {
	return errors.Errorf("%s %s", HashingFailed, fmt.Sprintf(format, args...))
}

func WrapHashingFailed(err error, format string, args ...any) error {
	return errors.Wrapf(err, "%s %s", HashingFailed, fmt.Sprintf(format, args...))
}

func IsHashingFailed(err error) bool {
	return Is(err, HashingFailed)
}

func HasHashingFailed(err error) bool {
	return Has(err, HashingFailed)
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
