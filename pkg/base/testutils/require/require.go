package require

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/stretchr/testify/require"
)

func NoError(t require.TestingT, err error, msgAndArgs ...any) {
	require.NoError(t, err, msgAndArgs...)
}

func NotNil(t require.TestingT, value any, msgAndArgs ...any) {
	require.NotNil(t, value, msgAndArgs...)
}

func OnlyInvalidParameterError(t require.TestingT, allowInvalid bool, err error, msgAndArgs ...any) {
	if err != nil && !allowInvalid {
		require.True(t, errs.IsParameterError(err), msgAndArgs...)
	}
}

func Error(t require.TestingT, err error, msgAndArgs ...any) {
	require.Error(t, err, msgAndArgs...)
}
