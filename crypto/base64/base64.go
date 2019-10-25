package base64

import (
	"encoding/base64"
	"encoding/binary"
)

// Copy from https://github.com/lestrrat/go-jwx/blob/master/internal/base64/base64.go

// EncodeToString - Encode byte to string
func EncodeToString(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

// EncodeUint64ToString - Encode Uint64
func EncodeUint64ToString(v uint64) string {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	return EncodeToString(data[i:])
}

// DecodeString - Decode string to byte
func DecodeString(src string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(src)
}
