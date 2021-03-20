package util

import "encoding/binary"
/* import "math" */

// For x and y non-negative intergers, toByte(x,y) returns the y-byte bytearray 
// containing the binary representation of x in big-endian byte-order.
func ToByte(x uint32, y uint) []byte {
	buffer := make([]byte, y)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

/* func Base_w(X []byte, w int, out_len int) []int {
	in := 0
	out := 0
	total := 0
	bits := 0
	consumed := 0
	var basew [out_len]int
	for consumed := 0; consumed < out_len; consumed++ {
		if(bits == 0) {
			total = X[in]
			in++
			bits += 8
		}
		bits -= math.Log2(w)
		basew[out] = (total >> bits) & (w - 1)
		out++
	}
	return basew
} */