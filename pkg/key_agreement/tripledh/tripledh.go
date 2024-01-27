package tripledh

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/ecsvdp/dhc"
)

// DeriveSecretLocal computes Triple Diffie-Hellman between two parties.
// When one party uses DeriveSecretLocal the other one must use DeriveSecretRemote and vice-versa.
// Other than that the computation is symmetric.
func DeriveSharedScalarLocal(a curves.Scalar, B curves.Point, x curves.Scalar, Y curves.Point,
) (secret curves.Scalar, err error) {
	unhashedSharedBytes, err := DeriveSharedBytesLocal(a, B, x, Y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secrets")
	}
	secret, err = a.ScalarField().Hash(unhashedSharedBytes)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot derive secret")
	}
	return secret, nil
}

// DeriveSharedScalarRemote computes Triple Diffie-Hellman between two parties.
// When one party uses DeriveSharedScalarRemote the other one must use DeriveSecretLocal and vice-versa.
// Other than that the computation is symmetric.
func DeriveSharedScalarRemote(A curves.Point, b curves.Scalar, X curves.Point, y curves.Scalar) (secret curves.Scalar, err error) {
	unhashedSharedBytes, err := DeriveSharedBytesRemote(A, b, X, y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secrets")
	}
	secret, err = b.ScalarField().Hash(unhashedSharedBytes)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot derive secret")
	}
	return secret, nil
}

// DeriveSharedBytesLocal computes the unhashed shared secret between two parties for the first party.
func DeriveSharedBytesLocal(a curves.Scalar, B curves.Point, x curves.Scalar, Y curves.Point) (unhashedSharedBytes []byte, err error) {
	return deriveSharedBytes(a, Y, x, B, x, Y, a, B)
}

// DeriveSharedBytesRemote computes the unhashed shared secret between two parties for the second party.
func DeriveSharedBytesRemote(A curves.Point, b curves.Scalar, X curves.Point, y curves.Scalar) (unhashedSharedBytes []byte, err error) {
	return deriveSharedBytes(y, A, b, X, y, X, b, A)
}

func deriveSharedBytes(
	ay curves.Scalar, AY curves.Point,
	bx curves.Scalar, BX curves.Point,
	xy curves.Scalar, XY curves.Point,
	ab curves.Scalar, AB curves.Point,
) (unhashedSharedBytes []byte, err error) {
	dh1, err := dhc.DeriveSharedSecretValue(ay, AY)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret dh1")
	}
	dh2, err := dhc.DeriveSharedSecretValue(bx, BX)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret dh2")
	}
	dh3, err := dhc.DeriveSharedSecretValue(xy, XY)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret dh3")
	}
	dh4, err := dhc.DeriveSharedSecretValue(ab, AB)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret dh4")
	}
	unhashedSharedBytes = bytes.Join([][]byte{dh1.Bytes(), dh2.Bytes(), dh3.Bytes(), dh4.Bytes()}, nil)
	return unhashedSharedBytes, nil
}
