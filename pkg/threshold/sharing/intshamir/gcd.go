package intshamir

func ExtendedGCD(a, b int64) (gcd, x, y int64) {
	oldS, s := int64(1), int64(0)
	oldR, r := a, b

	for r != 0 {
		q := oldR / r
		oldR, r = r, oldR-q*r
		oldS, s = s, oldS-q*s
	}
	t := (oldR - oldS*a) / b

	return oldS, t, oldR
}
