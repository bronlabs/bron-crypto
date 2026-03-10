package accessstructures

import (
	"iter"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
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
		out, err = unanimity.InducedMSP(f, ac)
	case *threshold.Threshold:
		out, err = threshold.InducedMSP(f, ac)
	case *hierarchical.HierarchicalConjunctiveThreshold:
		out, err = hierarchical.InducedMSP(f, ac)
	case *cnf.CNF:
		out, err = cnf.InducedMSP(f, ac)
	default:
		var ascnf *cnf.CNF
		ascnf, err = cnf.ConvertToCNF(ac)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to convert access structure to CNF for MSP induction")
		}
		out, err = cnf.InducedMSP(f, ascnf)
	}
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to induce MSP from access structure")
	}
	return out, nil
}
