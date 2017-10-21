package main

import (
	"net/url"
	"strconv"
)

func decodeBase16(base16 string) []byte {
	decoded := []byte{}
	for i := 0; i < len(base16); i += 2 {
		v, _ := strconv.ParseInt(base16[i:i+2], 16, 8)
		decoded = append(decoded, byte(v))
	}
	return decoded
}

func unescape(str []byte) []byte {
	d, _ := url.PathUnescape(string(str))
	return []byte(d)
}

func escape(str []byte) []byte {
	escapedString := ""
	for _, c := range str {
		switch c {
		case '+':
			escapedString += "%2B"
		case '%':
			escapedString += "%25"
		default:
			escapedString += string(c)
		}
	}
	return []byte(escapedString)
}

func checksum(data []byte) byte {
	sum := 0
	for _, v := range data {
		sum += int(v) % 16
	}
	return byte(sum % 16)
}
