package tripledh

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/dh"
)

// DeriveSecretLocal computes Triple Diffie-Hellman between two parties.
// When one party uses DeriveSecretLocal the other one must use DeriveSecretRemote and vice-versa.
// Other than that the computation is symmetric.
//

func DeriveSecretLocal(a curves.Scalar, B curves.Point, x curves.Scalar, Y curves.Point) (secret curves.Scalar, err error) {
	dh1, err := dh.DiffieHellman(a, Y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secrets")
	}
	dh2, err := dh.DiffieHellman(x, B)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot derive secret")
	}
	dh3, err := dh.DiffieHellman(x, Y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh4, err := dh.DiffieHellman(a, B)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	res, err := a.ScalarField().Hash(slices.Concat(dh1.Bytes(), dh2.Bytes(), dh3.Bytes(), dh4.Bytes()))
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot derive secret")
	}
	return res, nil
}

// DeriveSharedScalarRemote computes Triple Diffie-Hellman between two parties.
// When one party uses DeriveSharedScalarRemote the other one must use DeriveSecretLocal and vice-versa.
// Other than that the computation is symmetric.
//

func DeriveSecretRemote(A curves.Point, b curves.Scalar, X curves.Point, y curves.Scalar) (secret curves.Scalar, err error) {
	dh1, err := dh.DiffieHellman(y, A)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secrets")
	}
	dh2, err := dh.DiffieHellman(b, X)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot derive secret")
	}
	dh3, err := dh.DiffieHellman(y, X)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh4, err := dh.DiffieHellman(b, A)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	res, err := A.Curve().ScalarField().Hash(slices.Concat(dh1.Bytes(), dh2.Bytes(), dh3.Bytes(), dh4.Bytes()))
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot derive secret")
	}
	return res, nil
}
