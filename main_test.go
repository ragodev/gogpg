package main

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func BenchmarkDecrypt(b *testing.B) {
	gs, _ := New(`C:\cygwin64\home\Zack\.gnupg\secring.gpg`, `C:\cygwin64\home\Zack\.gnupg\pubring.gpg`)
	gs.Init("Testy McTestFace", "1234")
	for n := 0; n < b.N; n++ {
		data, _ := ioutil.ReadFile("test.txt.asc")
		gs.Decrypt(data)
	}
}

func TestListing(t *testing.T) {
	gs, _ := New(`C:\cygwin64\home\Zack\.gnupg\secring.gpg`, `C:\cygwin64\home\Zack\.gnupg\pubring.gpg`)
	keys, err := gs.ListPrivateKeys()
	assert.Equal(t, true, stringInSlice("Testy McTestFace", keys))
	assert.Equal(t, nil, err)

	keys, err = gs.ListPublicKeys()
	assert.Equal(t, true, stringInSlice("Testy McTestFace", keys))
	assert.Equal(t, nil, err)
}

func TestGeneral(t *testing.T) {
	gs, err := New(`C:\cygwin64\home\Zack\.gnupg\secring.gpg`, `C:\cygwin64\home\Zack\.gnupg\pubring.gpg`)
	assert.Equal(t, nil, err)
	gs.Init("Testy McTestFace", "1234")
	data, _ := ioutil.ReadFile("testing/hello.txt.asc")
	decrypted, err := gs.Decrypt(data)
	assert.Equal(t, nil, err)
	assert.Equal(t, "Hello, world.\n", decrypted)

	encrypted, err := gs.Encrypt("Hello, world.\n")
	assert.Equal(t, nil, err)
	decrypted, err = gs.Decrypt([]byte(encrypted))
	assert.Equal(t, nil, err)
	assert.Equal(t, "Hello, world.\n", decrypted)
}
