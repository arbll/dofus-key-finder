// Package decrypt finds the repeating XOR key length used for encrypted Dofus maps.
package decrypt

// Each map cell has ten bytes. These are the observed plaintext characters at
// each byte position. The sets combine plaintext maps in data/maps.csv with the
// published position statistics at https://arthur.bell.al/etc/cell_stats.json.
const cellSize = 10

const cellAlphabet = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

var cellCharacters = [cellSize]string{
	"GHOPab",
	"0123457AIKLNOPRZabcdefghijklmnoprstuwxyz",
	"2345678ACFGHIJKLMNOPQRSVWXYZ_abcdefghijklmnopqrstuvwxyz",
	cellAlphabet,
	"048CGKOQSWefghimqsu",
	"-012345678ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz",
	cellAlphabet,
	"0134GHJKLNOSWXYZabcdefghijklmnpqrtuvwxy",
	cellAlphabet,
	cellAlphabet,
}
