package ot

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrFailed          = errs.New("failed")
	ErrRound           = errs.New("invalid round")
)
