package tags

const (
	SimpleModulusTag         = 5006
	OddPrimeFactorsTag       = 5007
	OddPrimeSquareFactorsTag = 5008
)

const (
	RSAGroupKnownOrderTag = 5010 + iota
	RSAGroupKnownOrderElementTag
	RSAGroupUnknownOrderTag
	RSAGroupUnknownOrderElementTag
	PaillierGroupKnownOrderTag
	PaillierGroupKnownOrderElementTag
	PaillierGroupUnknownOrderTag
	PaillierGroupUnknownOrderElementTag
)

const (
	ThresholdGateAccessStructureTag = 5050 + iota
	CNFAccessStructureTag
	HierarchicalConjunctiveThresholdAccessStructureTag
	ThresholdAccessStructureTag
	UnanimityAccessStructureTag
)
