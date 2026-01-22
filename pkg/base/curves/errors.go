package curves

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrFailed represents a generic failure.
	ErrFailed = errs.New("failed")
	// ErrInvalidLength reports invalid length inputs.
	ErrInvalidLength = errs.New("invalid length")
	// ErrInvalidCoordinates reports invalid curve coordinates.
	ErrInvalidCoordinates = errs.New("invalid coordinates")
	// ErrInvalidArgument reports invalid arguments.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrSerialisation reports serialisation or deserialisation errors.
	ErrSerialisation = errs.New("serialisation error")
	// ErrNil reports nil arguments.
	ErrNil = errs.New("nil")
	// ErrRandomSample reports random sampling failures.
	ErrRandomSample = errs.New("random sample failed")
)
