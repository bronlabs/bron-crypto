package accessstructures_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
)

func _[E algebra.PrimeFieldElement[E]]() {
	var (
		_ accessstructures.Linear = (*cnf.CNF)(nil)
		_ accessstructures.Linear = (*threshold.Threshold)(nil)
		_ accessstructures.Linear = (*hierarchical.HierarchicalConjunctiveThreshold)(nil)
		_ accessstructures.Linear = (*unanimity.Unanimity)(nil)
	)
}
