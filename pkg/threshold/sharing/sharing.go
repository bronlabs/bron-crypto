package sharing

import (
	"io"

	"golang.org/x/exp/constraints"

	"github.com/bronlabs/krypton-primitives/pkg/base/types"
)

type Share interface {
	SharingId() types.SharingID
}

type Scheme[S Share, W any] interface {
	Deal(secret W, prng io.Reader) (shares map[types.SharingID]S, err error)
	Open(shares ...S) (secret W, err error)
}

type LinearScheme[S Share, W any, SC any] interface {
	Scheme[S, W]

	ShareAdd(lhs, rhs S) S
	ShareAddValue(lhs S, rhs W) S
	ShareSub(lhs, rhs S) S
	ShareSubValue(lhs S, rhs W) S
	ShareNeg(lhs S) S
	ShareMul(lhs S, rhs SC) S
}

type VerifiableScheme[S Share, W any, SC any, V any] interface {
	Scheme[S, W]

	DealVerifiable(secret W, prng io.Reader) (shares map[types.SharingID]S, verification V, err error)
	VerifyShare(share S, verification V) (err error)
}

type LinearVerifiableScheme[S Share, W any, SC any, V any] interface {
	LinearScheme[S, W, SC]
	VerifiableScheme[S, W, SC, V]

	VerificationAdd(lhs, rhs V) V
	VerificationAddValue(lhs V, rhs W) V
	VerificationSub(lhs, rhs V) V
	VerificationSubValue(lhs V, rhs W) V
	VerificationNeg(lhs V) V
	VerificationMul(lhs V, rhs SC) V
}

func AddSharesMap[M ~map[K]S, S Share, W, SC any, K constraints.Ordered](scheme LinearScheme[S, W, SC], lhs, rhs M) M {
	result := make(M)
	for i, l := range lhs {
		r := rhs[i]
		result[i] = scheme.ShareAdd(l, r)
	}

	return result
}

func AddSharesValueMap[M ~map[K]S, S Share, W, SC any, K constraints.Ordered](scheme LinearScheme[S, W, SC], lhs M, rhs W) M {
	result := make(M)
	for i, l := range lhs {
		result[i] = scheme.ShareAddValue(l, rhs)
	}

	return result
}

func SubSharesMap[M ~map[K]S, S Share, W, SC any, K constraints.Ordered](scheme LinearScheme[S, W, SC], lhs, rhs M) M {
	result := make(M)
	for i, l := range lhs {
		r := rhs[i]
		result[i] = scheme.ShareSub(l, r)
	}

	return result
}

func SubSharesValueMap[M ~map[K]S, S Share, W, SC any, K constraints.Ordered](scheme LinearScheme[S, W, SC], lhs M, rhs W) M {
	result := make(M)
	for i, l := range lhs {
		result[i] = scheme.ShareSubValue(l, rhs)
	}

	return result
}

func NegSharesMap[M ~map[K]S, S Share, W, SC any, K constraints.Ordered](scheme LinearScheme[S, W, SC], lhs M) M {
	result := make(M)
	for i, l := range lhs {
		result[i] = scheme.ShareNeg(l)
	}

	return result
}

func MulSharesMap[M ~map[K]S, S Share, W, SC any, K constraints.Ordered](scheme LinearScheme[S, W, SC], lhs M, rhs SC) M {
	result := make(M)
	for k, l := range lhs {
		result[k] = scheme.ShareMul(l, rhs)
	}

	return result
}
