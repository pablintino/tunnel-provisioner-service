package utils

func Max[T int | uint](a, b T) T {
	if a < b {
		return b
	}
	return a
}
