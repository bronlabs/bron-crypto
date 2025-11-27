package binrep3

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

const (
	Name sharing.Name = "BinaryReplicated(2,3)"
)

var (
	ErrInvalidArgument = errs2.New("Invalid argument")
	ErrInvalidShare    = errs2.New("Invalid share")
)
