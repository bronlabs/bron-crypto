package randfischlin

func isAllZeros(data []byte) bool {
	zeros := byte(0)
	for _, b := range data {
		zeros |= b
	}
	return zeros == 0
}
