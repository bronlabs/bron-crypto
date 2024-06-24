package rb

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"hash/fnv"
	"slices"
)

var (
	_ types.AuthKey = (*AuthIdentityKey)(nil)
)

// AuthIdentityKey is an identity as used in SDK, i.e. P256 keys
type AuthIdentityKey struct {
	secretKey curves.Scalar
	publicKey curves.Point
}

func NewAuthIdentity() (types.AuthKey, error) {
	sk, err := p256.NewCurve().ScalarField().Random(crand.Reader)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}
	pk := p256.NewCurve().ScalarBaseMult(sk)

	return &AuthIdentityKey{
		secretKey: sk,
		publicKey: pk,
	}, nil
}

func (k *AuthIdentityKey) String() string {
	return hex.EncodeToString(k.publicKey.ToAffineCompressed())
}

func (k *AuthIdentityKey) PublicKey() curves.Point {
	return k.publicKey
}

func (k *AuthIdentityKey) Verify(signature []byte, message []byte) error {
	panic("not implemented - used for broadcast only")
}

func (k *AuthIdentityKey) Equal(rhs types.IdentityKey) bool {
	return slices.Equal(k.publicKey.ToAffineCompressed(), rhs.PublicKey().ToAffineCompressed())
}

func (k *AuthIdentityKey) HashCode() uint64 {
	h := fnv.New64()
	if _, err := h.Write(k.publicKey.ToAffineCompressed()); err != nil {
		return 0
	}
	return h.Sum64()
}

func (k *AuthIdentityKey) MarshalJSON() ([]byte, error) {
	panic("implement me")
}

func (k *AuthIdentityKey) Sign(message []byte) []byte {
	panic("implement me")
}

func (k *AuthIdentityKey) PrivateKey() curves.Scalar {
	return k.secretKey
}
