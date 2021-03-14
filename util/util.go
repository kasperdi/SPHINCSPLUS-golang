package util

import "encoding/binary"

// For x and y non-negative intergers, toByte(x,y) returns the y-byte bytearray 
// containing the binary representation of x in big-endian byte-order.
func ToByte(x uint32, y uint) []byte {
	buffer := make([]byte, y)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}