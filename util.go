package main

import "strconv"
import "net/url"

const HEX_CHARS string = "0123456789ABCDEF";

func decodeBase16(base16 string) []byte {
	decoded := []byte{}
	for i := 0; i < len(base16); i += 2 {
		v, _ := strconv.ParseInt(base16[i:i+2], 16, 8)
		decoded = append(decoded, byte(v))
	}
	return decoded
}

func unescape(str []byte) []byte {
	d, _ := url.QueryUnescape(string(str))
	return []byte(d)
}

func checksum(data []byte) byte {
	var sum = byte(0);
	for _, v := range data {
		sum += v % 16;
	}
	return sum % 16;
}