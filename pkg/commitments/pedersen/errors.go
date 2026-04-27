package pedersen

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument is returned when a caller-supplied input violates a precondition (nil, out of range, mismatched group, etc.).
	ErrInvalidArgument = errs.New("invalid arguments")
	// ErrFailed is returned when a Pedersen operation fails for reasons that are not attributable to a specific caller-supplied input.
	ErrFailed = errs.New("failed")
	// ErrSerialisation is returned when CBOR encoding or decoding of a Pedersen value fails.
	ErrSerialisation = errs.New("serialisation/deserialisation failed")
)
