package rwdabe

import (
	//"basics/crypto/bn128"
	//"basics/crypto/lwdabe"
	"crypto/rand"
	"fmt"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMAABE(t *testing.T) {
	// create new MAABE struct with Global Parameters
	_, gt, _ := bn128.RandomGT(rand.Reader)
	KDF(gt)
	maabe := NewMAABE()

	// create three authorities, each with two attributes
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	auth1, err := maabe.NewMAABEAuth("auth1")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth1", err)
	}
	auth2, err := maabe.NewMAABEAuth("auth2")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth2", err)
	}
	auth3, err := maabe.NewMAABEAuth("auth3")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth3", err)
	}

	// create a msp struct out of the boolean formula
	msp, err := lib.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
	}

	// define the set of all public keys we use
	pks := []*MAABEPubKey{auth1.Pk, auth2.Pk, auth3.Pk}

	// choose a message
	msg := "Attack at dawn!"

	// encrypt the message with the decryption policy in msp
	ct, err := maabe.ABEEncrypt(msg, msp, pks)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}

	// also check for empty message
	msgEmpty := ""
	_, err = maabe.ABEEncrypt(msgEmpty, msp, pks)
	assert.Error(t, err)

	// use a pub keyring that is too small
	pksSmall := []*MAABEPubKey{auth1.Pk}
	_, err = maabe.ABEEncrypt(msg, msp, pksSmall)
	assert.Error(t, err)

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user
	key11, err := auth1.ABEKeyGen(gid, attribs1[0])
	//keys1[1]
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	key12, err := auth1.ABEKeyGen(gid, attribs1[1])
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	// authority 2 issues keys to user
	key21, err := auth2.ABEKeyGen(gid, attribs2[0])
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	key22, err := auth2.ABEKeyGen(gid, attribs2[1])
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	// authority 3 issues keys to user
	//key31, err := auth3.ABEKeyGen(gid, attribs3[0])
	userSk := RandomInt()
	userPk := new(bn128.G1).ScalarMult(auth3.Maabe.G1, userSk)
	key31Enc, _ := auth3.ABEKeyGen(gid, attribs3[0], userPk)
	proof, err := auth3.KeyGenPrimeAndGenProofs(key31Enc, userPk)
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	res, err := maabe.CheckKey(userPk, key31Enc, proof)
	if !res {
		t.Fatalf("Failed to checkKey attribute keys: %v\n", err)
	}
	key31 := auth3.GetKey(key31Enc, userSk)
	fmt.Println("GetKey", key31Enc.Key)
	key32, err := auth3.ABEKeyGen(gid, attribs3[1])
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	// try and generate key for an attribute that does not belong to the
	// authority (or does not exist)
	//_, err = auth3.KeyGen(gid, []string{"auth3:at3"})
	//assert.Error(t, err)

	// user tries to decrypt with different key combos
	ks1 := []*MAABEKey{key11, key21, key31} // ok
	ks2 := []*MAABEKey{key12, key22, key32} // ok
	ks3 := []*MAABEKey{key11, key22}        // not ok
	ks4 := []*MAABEKey{key12, key21}        // not ok
	ks5 := []*MAABEKey{key31, key32}        // ok

	// try to decrypt all messages
	msg1, err := maabe.ABEDecrypt(ct, ks1)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 1: %v\n", err)
	}
	assert.Equal(t, msg, msg1)

	msg2, err := maabe.ABEDecrypt(ct, ks2)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 2: %v\n", err)
	}
	assert.Equal(t, msg, msg2)

	_, err = maabe.ABEDecrypt(ct, ks3)
	assert.Error(t, err)

	_, err = maabe.ABEDecrypt(ct, ks4)
	assert.Error(t, err)
	msg5, err := maabe.ABEDecrypt(ct, ks5)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 5: %v\n", err)
	}
	assert.Equal(t, msg, msg5)

	// generate keys with a different GID
	gid2 := "gid2"
	// authority 1 issues keys to user
	foreignKeys, err := auth1.ABEKeyGen(gid2, "auth1:at1")
	if err != nil {
		t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth1:at1", err)
	}
	foreignKey11 := foreignKeys
	// join two users who have sufficient attributes together, but not on their
	// own
	ks6 := []*MAABEKey{foreignKey11, key21}
	// try and decrypt
	_, err = maabe.ABEDecrypt(ct, ks6)
	assert.Error(t, err)

}
