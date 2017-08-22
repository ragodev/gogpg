package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// GPGStore is the basic store object.
type GPGStore struct {
	secretKeyring     string
	publicKeyring     string
	identity          string
	passphrase        string
	privateEntity     *openpgp.Entity
	privateKeyToUse   []*openpgp.Entity
	publicEntity      *openpgp.Entity
	publicKeyToUse    []*openpgp.Entity
	privateEntityList openpgp.EntityList
}

func New(secretKeyring, publicKeyring string) (*GPGStore, error) {
	gs := new(GPGStore)
	gs.secretKeyring = secretKeyring
	gs.publicKeyring = publicKeyring
	return gs, nil
}

func (gs *GPGStore) ListPrivateKeys() ([]string, error) {
	keyringFileBuffer, err := os.Open(gs.secretKeyring)
	if err != nil {
		panic(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}
	keys := []string{}
	for _, key := range entityList {
		for _, id := range key.Identities {
			keys = append(keys, strings.Split(strings.Split(id.Name, " <")[0], " (")[0])
		}
	}
	return keys, nil
}

func (gs *GPGStore) ListPublicKeys() ([]string, error) {
	keyringFileBuffer, err := os.Open(gs.publicKeyring)
	if err != nil {
		panic(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}
	keys := []string{}
	for _, key := range entityList {
		for _, id := range key.Identities {
			keys = append(keys, strings.Split(strings.Split(id.Name, " <")[0], " (")[0])
		}
	}
	return keys, nil
}

func (gs *GPGStore) Init(identity, passphrase string) (*GPGStore, error) {
	gs.identity = identity
	gs.passphrase = passphrase

	// Open the private key file
	var entityList []*openpgp.Entity
	keyringFileBuffer, err := os.Open(gs.secretKeyring)
	if err != nil {
		panic(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}
	gs.privateKeyToUse = make([]*openpgp.Entity, 1)
	for _, key := range entityList {
		for _, id := range key.Identities {
			if strings.Split(strings.Split(id.Name, " <")[0], " (")[0] == identity {
				gs.privateKeyToUse[0] = key
				gs.privateEntity = key
			}
		}
	}
	gs.privateEntityList = entityList
	keyringFileBuffer.Close()

	// Open the public key file
	keyringFileBuffer, err = os.Open(gs.publicKeyring)
	if err != nil {
		panic(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}
	gs.publicKeyToUse = make([]*openpgp.Entity, 1)
	for _, key := range entityList {
		for _, id := range key.Identities {
			if strings.Split(strings.Split(id.Name, " <")[0], " (")[0] == identity {
				gs.publicKeyToUse[0] = key
				gs.publicEntity = key
			}
		}
	}
	keyringFileBuffer.Close()

	return gs, nil
}

func (gs *GPGStore) Decrypt(data []byte) (string, error) {
	passphraseByte := []byte(gs.passphrase)
	gs.privateEntity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range gs.privateEntity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	result, err := armor.Decode(bytes.NewBuffer(data))
	if err != nil {
		log.Fatal(err)
	}

	md, err := openpgp.ReadMessage(result.Body, gs.privateEntityList, nil, nil)
	if err != nil {
		panic(err)
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		panic(err)
	}
	decStr := string(bytes)
	return decStr, nil
}

func (gs *GPGStore) Encrypt(secretString string) (string, error) {
	buf := new(bytes.Buffer)
	msg, _ := armor.Encode(buf, "PGP MESSAGE", nil)
	w, err := openpgp.Encrypt(msg, gs.publicKeyToUse, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	_, err = w.Write([]byte(secretString))
	if err != nil {
		panic(err)
	}
	err = w.Close()
	if err != nil {
		panic(err)
	}
	msg.Close()

	bytes, err := ioutil.ReadAll(buf)
	str := string(bytes)
	return str, nil
}

func gpgDecryptFile(file string, secretKeyring string, identify string, passphrase string) (string, error) {
	data, err := ioutil.ReadFile("test.txt.asc")
	if err != nil {
		panic(err)
	}

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		panic(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}
	for _, e := range entityList {
		for keyIdentity := range e.Identities {
			if keyIdentity == identify {
				entity = e
			}
		}
	}

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt it with the contents of the private key
	result, err := armor.Decode(bytes.NewBuffer(data))
	if err != nil {
		log.Fatal(err)
	}
	md, err := openpgp.ReadMessage(result.Body, entityList, nil, nil)
	if err != nil {
		panic(err)
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		panic(err)
	}
	decStr := string(bytes)
	return decStr, nil
}

func encTest(secretString string, publicKeyring string, identify string) (string, error) {
	log.Println("Secret to hide:", secretString)
	log.Println("Public Keyring:", publicKeyring)

	// Read in public key
	log.Println(publicKeyring)
	keyringFileBuffer, err := os.Open(publicKeyring)
	if err != nil {
		panic(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}

	// encrypt string
	fmt.Println(entityList[0].Identities)
	keyToUse := make([]*openpgp.Entity, 1)
	for _, key := range entityList {
		for _, id := range key.Identities {
			fmt.Println(id.Name)
			if id.Name == identify {
				keyToUse[0] = key
			}
		}
	}

	buf := new(bytes.Buffer)
	msg, _ := armor.Encode(buf, "PGP MESSAGE", nil)
	w, err := openpgp.Encrypt(msg, keyToUse, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	_, err = w.Write([]byte(secretString))
	if err != nil {
		panic(err)
	}
	err = w.Close()
	if err != nil {
		panic(err)
	}
	msg.Close()

	// Encode to base64
	bytes, err := ioutil.ReadAll(buf)
	str := string(bytes)
	log.Println("Encrypted Secret:", str)

	return str, nil
}

func main() {

	gs, err := New(`C:\cygwin64\home\Zack\.gnupg\secring.gpg`, `C:\cygwin64\home\Zack\.gnupg\pubring.gpg`)
	gs.Init("Testy McTestFace", "1234")
	if err != nil {
		panic(err)
	}
	data, _ := ioutil.ReadFile("test.txt.asc")
	fmt.Println(gs.Decrypt(data))
	fmt.Println(gs.Encrypt("hello world"))
}
