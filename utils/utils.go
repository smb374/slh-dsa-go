package utils

import "golang.org/x/exp/constraints"

const (
	W    = 16
	LEN2 = 3
	LGw  = 4
)

func ToInt(x []byte, n int) int {
	total := 0
	for i := 0; i < n; i++ {
		total = (total << 8) + int(x[i])
	}
	return total
}

func ToByte(x int, n int) []byte {
	buf := make([]byte, n)
	total := x
	for i := 0; i < n; i++ {
		buf[n-1-i] = byte(total & 0xff)
		total >>= 8
	}
	return buf
}

func Base2b(x []byte, b int, out_len int) []int {
	in := 0
	bits := 0
	total := 0
	baseb := make([]int, out_len)

	for out := 0; out < out_len; out++ {
		for bits < b {
			total = (total << 8) + int(x[in])
			in++
			bits += 8
		}
		bits -= b
		baseb[out] = (total >> bits) & ((1 << b) - 1)
	}
	return baseb
}

func DivCeil[T constraints.Integer](a T, b T) T {
	result := a / b
	if a%b != 0 {
		return result + 1
	} else {
		return result
	}
}
