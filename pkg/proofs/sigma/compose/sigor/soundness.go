package sigor

// composedSpecialSoundness returns the special soundness of an OR composition whose
// branches are k_1-, ..., k_m-special sound: prod_i (k_i - 1) + 1.
//
// Accepting OR transcripts with the same commitment vector and pairwise distinct
// challenges have pairwise distinct branch-challenge tuples (e_1, ..., e_m), since the
// tuple determines the challenge. If branch i had at most k_i - 1 distinct challenges
// among them, there would be at most prod_i (k_i - 1) tuples, so one more transcript
// forces some branch i to hold k_i accepting transcripts with distinct challenges and
// the same commitment, from which its extractor recovers a witness. The bound is
// tight: a prover holding k_i - 1 simulated transcripts per branch, which
// (k_i - 1)-simulatable protocols such as batch Schnorr permit, can assemble
// prod_i (k_i - 1) accepting OR transcripts without any witness. For 2-special sound
// branches the result is 2, independently of m.
func composedSpecialSoundness(branches ...uint) uint {
	product := uint(1)
	for _, k := range branches {
		product *= k - 1
	}
	return product + 1
}
