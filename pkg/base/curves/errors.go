package curves

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrFailed represents a generic failure.
	ErrFailed = errs2.New("failed")
	// ErrInvalidLength reports invalid length inputs.
	ErrInvalidLength = errs2.New("invalid length")
	// ErrInvalidCoordinates reports invalid curve coordinates.
	ErrInvalidCoordinates = errs2.New("invalid coordinates")
	// ErrInvalidArgument reports invalid arguments.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrSerialisation reports serialisation or deserialisation errors.
	ErrSerialisation = errs2.New("serialisation error")
	// ErrNil reports nil arguments.
	ErrNil = errs2.New("nil")
	// ErrRandomSample reports random sampling failures.
	ErrRandomSample = errs2.New("random sample failed")
)
