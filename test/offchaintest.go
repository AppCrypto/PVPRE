package main

import (
	"basics/crypto/rwdabe"
	"fmt"
	"time"

	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
)

func main() {

	maabe := rwdabe.NewMAABE()
	const times int64 = 100
	// create three authorities, each with two attributes
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	attribs4 := []string{"auth4:at1", "auth4:at2"}
	auth1, _ := maabe.NewMAABEAuth("auth1")
	auth2, _ := maabe.NewMAABEAuth("auth2")
	auth3, _ := maabe.NewMAABEAuth("auth3")
	auth4, _ := maabe.NewMAABEAuth("auth4")
	// create a msp struct out of the boolean formula
	//msp, _ := lib.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	msp, _ := lib.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth4:at1", false)
	// define the set of all public keys we use
	pks := []*rwdabe.MAABEPubKey{auth1.Pk, auth2.Pk, auth3.Pk, auth4.Pk}

	// choose a message
	msg := "Attack at dawn!"

	// encrypt the message with the decryption policy in msp
	ct, _ := maabe.ABEEncrypt(msg, msp, pks)

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user
	key11, _ := auth1.ABEKeyGen(gid, attribs1[0])
	//keys1[1]
	key12, _ := auth1.ABEKeyGen(gid, attribs1[1])
	// authority 2 issues keys to user
	key21, _ := auth2.ABEKeyGen(gid, attribs2[0])
	key22, _ := auth2.ABEKeyGen(gid, attribs2[1])
	key41, _ := auth4.ABEKeyGen(gid, attribs4[0])
	key42, _ := auth4.ABEKeyGen(gid, attribs4[1])

	// authority 3 issues keys to user
	//key31, err := auth3.ABEKeyGen(gid, attribs3[0])
	userSk := rwdabe.RandomInt()
	userPk := new(bn128.G1).ScalarMult(auth3.Maabe.G1, userSk)
	key31Enc, _ := auth3.ABEKeyGen(gid, attribs3[0], userPk)
	proof, _ := auth3.KeyGenPrimeAndGenProofs(key31Enc, userPk)

	startts := time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_, _ = auth4.ABEKeyGen(gid, attribs4[1])
	}
	endts := time.Now().UnixNano() / 1e3
	fmt.Printf("ABEKeyGen time cost: %v μs\n ", (endts-startts)/times)

	startts = time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_, _ = auth3.KeyGenPrimeAndGenProofs(key31Enc, userPk)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("GenProofs time cost: %v μs\n ", (endts-startts)/times)

	startts = time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_, _ = maabe.CheckKey(userPk, key31Enc, proof)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("Off-chain CheckKey time cost: %v μs\n ", (endts-startts)/times)

	key31 := auth3.GetKey(key31Enc, userSk)

	//fmt.Println("GetKey", key31Enc.Key)

	startts = time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_ = auth3.GetKey(key31Enc, userSk)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("GetKey time cost: %v μs\n", (endts-startts)/times)

	//key32, err := auth3.ABEKeyGen(gid, attribs3[1])
	// user tries to decrypt with different key combos
	ks1 := []*rwdabe.MAABEKey{key11, key12, key21, key22, key31, key41, key42} // ok

	// try to decrypt all messages
	msg1, _ := maabe.ABEDecrypt(ct, ks1)

	fmt.Println("msg1", msg1)
}
