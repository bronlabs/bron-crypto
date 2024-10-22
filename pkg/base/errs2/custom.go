package errs2

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const (
	Argument          = Tag("argument")
	Coordinates       = Tag("coordinates")
	Curve             = Tag("curve")
	Hashing           = Tag("hashing")
	IdentifiableAbort = Tag1[types.IdentityKey]("identifiable_abort")
	IsIdentity        = Tag("is_identity")
	IsNil             = Tag("is_nil")
	IsZero            = Tag("is_zero")
	Length            = Tag("length")
	Membership        = Tag("membership")
	Missing           = Tag("missing")
	RandomSample      = Tag("random_sample")
	Round             = Tag("round")
	Serialisation     = Tag("serialisation")
	Size              = Tag("size")
	TotalAbort        = Tag("total_abort")
	Type              = Tag("type")
	Validation        = Tag("validation")
	Value             = Tag("value")
	Verification      = Tag("verification")
)

func init() {
	RegisterTag(Argument, "invalid argument")
	RegisterTag(Coordinates, "invalid coordinates")
	RegisterTag(Curve, "invalid curve")
	RegisterTag(Hashing, "hashing failed")
	RegisterTag1(IdentifiableAbort, "received identifiable abort")
	RegisterTag(IsIdentity, "value is identity")
	RegisterTag(IsNil, "value is nil")
	RegisterTag(IsZero, "value is zero")
	RegisterTag(Length, "invalid length")
	RegisterTag(Membership, "invalid membership")
	RegisterTag(Missing, "missing value")
	RegisterTag(RandomSample, "random sampling failed")
	RegisterTag(Round, "round failed")
	RegisterTag(Serialisation, "serialisation failed")
	RegisterTag(Size, "invalid size")
	RegisterTag(TotalAbort, "total abort")
	RegisterTag(Type, "invalid type")
	RegisterTag(Validation, "validation failed")
	RegisterTag(Value, "invalid value")
	RegisterTag(Verification, "verification failed")
}

func Aborter(errorChain error) (types.IdentityKey, error) {
	err := Extract(errorChain, IdentifiableAbort)
	if err == nil {
		return nil, Type.New("no identifiable abort found")
	}
	out, ok := err.(TaggedError1[types.IdentityKey])
	if !ok {
		return nil, Type.New("invalid identifiable abort type")
	}
	return out.Arg(), nil
}
