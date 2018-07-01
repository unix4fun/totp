package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

const (
	Rfc6238Secret    = "12345678901234567890"
	Rfc6238Secret256 = "12345678901234567890123456789012"
	Rfc6238Secret512 = "1234567890123456789012345678901234567890123456789012345678901234"
)

type TestVectorEntry struct {
	f func() hash.Hash // hash function to use
	t uint64           // time to use
	s string           // secret to use
	e uint32           // expected value
}

var (
	RFCTestVectors = []TestVectorEntry{
		// vector 1
		{sha1.New, 59, Rfc6238Secret, 94287082},
		{sha256.New, 59, Rfc6238Secret256, 46119246},
		{sha512.New, 59, Rfc6238Secret512, 90693936},
		// vector 2
		{sha1.New, 1111111109, Rfc6238Secret, 7081804},
		{sha256.New, 1111111109, Rfc6238Secret256, 68084774},
		{sha512.New, 1111111109, Rfc6238Secret512, 25091201},
		// vector 3
		{sha1.New, 1111111111, Rfc6238Secret, 14050471},
		{sha256.New, 1111111111, Rfc6238Secret256, 67062674},
		{sha512.New, 1111111111, Rfc6238Secret512, 99943326},
		// vector 4
		{sha1.New, 1234567890, Rfc6238Secret, 89005924},
		{sha256.New, 1234567890, Rfc6238Secret256, 91819424},
		{sha512.New, 1234567890, Rfc6238Secret512, 93441116},
		// vector 5
		{sha1.New, 2000000000, Rfc6238Secret, 69279037},
		{sha256.New, 2000000000, Rfc6238Secret256, 90698825},
		{sha512.New, 2000000000, Rfc6238Secret512, 38618901},
		// vector 6
		{sha1.New, 20000000000, Rfc6238Secret, 65353130},
		{sha256.New, 20000000000, Rfc6238Secret256, 77737706},
		{sha512.New, 20000000000, Rfc6238Secret512, 47863826},
	}
)

func TestRfcVectors(t *testing.T) {
	for i, v := range RFCTestVectors {
		to := New(v.f, []byte(v.s), 8, 30)
		totp, err := to.Get(v.t)
		if err != nil {
			t.Fatalf("[%d] totp error: %v", i, err)
		}
		if totp != v.e {
			t.Fatalf("[%d] totp error expected: %08d vs %08d", i, v.e, totp)
		}
		t.Logf("[%d] totp: %08d expected: %08d", i, totp, v.e)
	}
}
