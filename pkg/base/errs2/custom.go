package errs2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const (
	Argument          = Kind("argument")
	Coordinates       = Kind("coordinates")
	Curve             = Kind("curve")
	Hashing           = Kind("hashing")
	IdentifiableAbort = Kind1[types.IdentityKey]("identifiable_abort")
	IsIdentity        = Kind("is_identity")
	IsNil             = Kind("is_nil")
	IsZero            = Kind("is_zero")
	Length            = Kind("length")
	Membership        = Kind("membership")
	Missing           = Kind("missing")
	RandomSample      = Kind("random_sample")
	Round             = Kind("round")
	Serialisation     = Kind("serialisation")
	Size              = Kind("size")
	TotalAbort        = Kind("total_abort")
	Type              = Kind("type")
	Validation        = Kind("validation")
	Value             = Kind("value")
	Verification      = Kind("verification")
)

func Aborter(errorChain error) (types.IdentityKey, error) {
	err := Extract(errorChain, IdentifiableAbort)
	if err == nil {
		return nil, Type.New("no identifiable abort found")
	}
	//nolint:errorlint // error package internals
	out, ok := err.(Kinded1Error[types.IdentityKey])
	if !ok {
		return nil, Type.New("invalid identifiable abort type")
	}
	return out.Arg(), nil
}
