package test_utils

import (
	crand "crypto/rand"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/signing/interactive"
)

func DoLindell17Sign(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*lindell17.Shard, alice, bob int, message []byte) (signature *ecdsa.Signature, err error) {
	primary, err := interactive.NewPrimaryCosigner(identities[alice], identities[bob], shards[alice], cohortConfig, sid, nil, crand.Reader)
	if primary == nil {
		return nil, errs.NewFailed("primary should not be nil")
	}
	if err != nil {
		return nil, err
	}

	secondary, err := interactive.NewSecondaryCosigner(identities[bob], identities[alice], shards[bob], cohortConfig, sid, nil, crand.Reader)
	if secondary == nil {
		return nil, errs.NewFailed("secondary should not be nil")
	}
	if err != nil {
		return nil, err
	}

	r1, err := primary.Round1()
	if err != nil {
		return nil, err
	}

	r2, err := secondary.Round2(r1)
	if err != nil {
		return nil, err
	}

	r3, err := primary.Round3(r2)
	if err != nil {
		return nil, err
	}

	r4, err := secondary.Round4(r3, message)
	if err != nil {
		return nil, err
	}

	signature, err = primary.Round5(r4, message)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
