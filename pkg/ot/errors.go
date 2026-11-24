package ot

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing, empty, or inconsistent inputs, such as
	// a message batch whose length is not a positive multiple of 8, or decoded
	// data whose messages do not have the width of the message type.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrSerialisation indicates a serialisation or deserialisation failure.
	ErrSerialisation = errs.New("serialisation error")
	// ErrRound indicates that a protocol round was invoked out of order.
	ErrRound = errs.New("invalid round")
	// ErrValidation indicates that a message received from the other party
	// failed validation.
	ErrValidation = errs.New("validation failed")
)
