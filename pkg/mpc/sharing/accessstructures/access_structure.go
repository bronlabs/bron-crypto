package accessstructures

import (
	"iter"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

// Monotone defines the common API for monotone sharing access
// structures.
type Monotone interface {
	// IsQualified reports whether the given shareholder IDs form a qualified set.
	IsQualified(ids ...ID) bool
	// Shareholders returns the universe of shareholders for this access structure.
	Shareholders() ds.Set[ID]
}

// Linear extends Monotone with the ability to enumerate maximal unqualified
// sets, which is required for MSP induction.
type Linear interface {
	Monotone
	// MaximalUnqualifiedSetsIter streams maximal unqualified sets of the access structure.
	MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]]
}

// ID uniquely identifies a shareholder.
type ID = internal.ID

// InducedMSP constructs a monotone span programme from a linear access
// structure. It dispatches to the most efficient construction for known
// concrete types and falls back to CNF conversion for unknown implementations.
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac Linear) (*msp.MSP[E], error) {
	var out *msp.MSP[E]
	var err error
	switch ac := ac.(type) {
	case *unanimity.Unanimity:
		out, err = unanimity.InducedByUnanimity(f, ac)
	case *threshold.Threshold:
		out, err = threshold.InducedMSPByThreshold(f, ac)
	case *hierarchical.HierarchicalConjunctiveThreshold:
		out, err = hierarchical.InducedMSPByHierarchicalConjunctiveThreshold(f, ac)
	case *cnf.CNF:
		out, err = cnf.InducedMSPByCNF(f, ac)
	default:
		var ascnf *cnf.CNF
		ascnf, err = cnf.ConvertToCNF(ac)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to convert access structure to CNF for MSP induction")
		}
		out, err = cnf.InducedMSPByCNF(f, ascnf)
	}
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to induce MSP from unanimity access structure")
	}
	return out, nil
}
