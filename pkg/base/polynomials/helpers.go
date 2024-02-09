package polynomials

import (
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

var scalarUnivariatePolynomialsSetsLock sync.RWMutex
var scalarUnivariatePolynomialsSets = make(map[string]*UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar])

func GetScalarUnivariatePolynomialsSet(scalarField curves.ScalarField) *UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar] {
	set := getScalarUnivariatePolynomialsSetIfExists(scalarField.Name())
	if set != nil {
		return set
	}

	scalarUnivariatePolynomialsSetsLock.Lock()
	defer scalarUnivariatePolynomialsSetsLock.Unlock()
	set, ok := scalarUnivariatePolynomialsSets[scalarField.Name()]
	if ok {
		return set
	}

	set = NewUnivariatePolynomialsSet[curves.ScalarField, curves.Scalar](scalarField)
	scalarUnivariatePolynomialsSets[scalarField.Name()] = set
	return set
}

func getScalarUnivariatePolynomialsSetIfExists(fieldName string) *UnivariatePolynomialsSet[curves.ScalarField, curves.Scalar] {
	scalarUnivariatePolynomialsSetsLock.RLock()
	defer scalarUnivariatePolynomialsSetsLock.RUnlock()
	set, ok := scalarUnivariatePolynomialsSets[fieldName]
	if ok {
		return set
	} else {
		return nil
	}
}
