package x3dh

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/ecsvdp/dhc"
)

// DeriveSecretLocal computes Triple Diffie-Hellman between two nodes.
// When one node uses DeriveSecretLocal the other one must use DeriveSecretRemote and vice-versa.
// Other than that the computation is symmetric.
//
//nolint:dupl // It is intended to have two seemingly identical functions for local and remote.
func DeriveSecretLocal(a curves.Scalar, B curves.Point, x curves.Scalar, Y curves.Point) (secret curves.Scalar, err error) {
	dh1, err := dhc.DeriveSharedSecretValue(a, Y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh2, err := dhc.DeriveSharedSecretValue(x, B)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh3, err := dhc.DeriveSharedSecretValue(x, Y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh4, err := dhc.DeriveSharedSecretValue(a, B)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	res, err := a.Curve().Scalar().Hash(bytes.Join([][]byte{dh1.Bytes(), dh2.Bytes(), dh3.Bytes(), dh4.Bytes()}, nil))
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot derive secret")
	}
	return res, nil
}

// DeriveSecretRemote computes Triple Diffie-Hellman between two nodes.
// When one node uses DeriveSecretRemote the other one must use DeriveSecretLocal and vice-versa.
// Other than that the computation is symmetric.
//
//nolint:dupl // It is intended to have two seemingly identical functions for local and remote.
func DeriveSecretRemote(A curves.Point, b curves.Scalar, X curves.Point, y curves.Scalar) (secret curves.Scalar, err error) {
	dh1, err := dhc.DeriveSharedSecretValue(y, A)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh2, err := dhc.DeriveSharedSecretValue(b, X)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh3, err := dhc.DeriveSharedSecretValue(y, X)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	dh4, err := dhc.DeriveSharedSecretValue(b, A)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive secret")
	}
	res, err := A.Curve().Scalar().Hash(bytes.Join([][]byte{dh1.Bytes(), dh2.Bytes(), dh3.Bytes(), dh4.Bytes()}, nil))
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "cannot derive secret")
	}
	return res, nil
}
