package errs2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var (
	Argument          = NewTag0("argument", "invalid argument")
	Coordinates       = NewTag0("coordinates", "invalid coordinates")
	Curve             = NewTag0("curve", "invalid curve")
	Hashing           = NewTag0("hashing", "hashing failed")
	IdentifiableAbort = NewTag1[types.IdentityKey]("identifiable_abort", "received identifiable abort")
	IsIdentity        = NewTag0("is_identity", "value is identity")
	IsNil             = NewTag0("is_nil", "value is nil")
	IsZero            = NewTag0("is_zero", "value is zero")
	Length            = NewTag0("length", "invalid length")
	Membership        = NewTag0("membership", "invalid membership")
	Missing           = NewTag0("missing", "missing value")
	RandomSample      = NewTag0("random_sample", "random sampling failed")
	Round             = NewTag0("round", "round failed")
	Serialisation     = NewTag0("serialisation", "serialisation failed")
	Size              = NewTag0("size", "invalid size")
	TotalAbort        = NewTag0("total_abort", "total abort")
	Type              = NewTag0("type", "invalid type")
	Validation        = NewTag0("validation", "validation failed")
	Value             = NewTag0("value", "invalid value")
	Verification      = NewTag0("verification", "verification failed")
)

func Aborter(errorChain error) (types.IdentityKey, error) {
	err := Extract(errorChain, IdentifiableAbort)
	if err == nil {
		return nil, Type.New("no identifiable abort found")
	}
	//nolint:errorlint // error package internals
	out, ok := err.(Tagged1Error[types.IdentityKey])
	if !ok {
		return nil, Type.New("invalid identifiable abort type")
	}
	return out.Arg(), nil
}
