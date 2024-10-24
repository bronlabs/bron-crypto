package errs2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const (
	Argument          = Tag0("argument")
	Coordinates       = Tag0("coordinates")
	Curve             = Tag0("curve")
	Hashing           = Tag0("hashing")
	IdentifiableAbort = Tag1[types.IdentityKey]("identifiable_abort")
	IsIdentity        = Tag0("is_identity")
	IsNil             = Tag0("is_nil")
	IsZero            = Tag0("is_zero")
	Length            = Tag0("length")
	Membership        = Tag0("membership")
	Missing           = Tag0("missing")
	RandomSample      = Tag0("random_sample")
	Round             = Tag0("round")
	Serialisation     = Tag0("serialisation")
	Size              = Tag0("size")
	TotalAbort        = Tag0("total_abort")
	Type              = Tag0("type")
	Validation        = Tag0("validation")
	Value             = Tag0("value")
	Verification      = Tag0("verification")
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
