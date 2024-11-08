package main

import (
	"basics/compile/contract"
	"basics/crypto/rwdabe"
	"basics/utils"
	"context"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
)

type ACJudge struct {
	Props []string `json:"props"`
	ACS   string   `json:"acs"`
}

func G1ToPoint(point *bn128.G1) contract.BasicsG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())
	//fmt.Println(g.Marshal())
	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	g1Point := contract.BasicsG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G2ToPoint(point *bn128.G2) contract.BasicsG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()
	//fmt.Println(point.Marshal())

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := contract.BasicsG2Point{
		X: [2]*big.Int{a1, a2},
		Y: [2]*big.Int{b1, b2},
	}
	return g2Point
}

func generateACPStr(n int) *ACJudge {

	attrs := make([]string, n)
	for i := 1; i < n+1; i++ {
		attrs[i-1] = "auth" + strconv.Itoa(i) + ":at1"
		//fmt.Println(strconv.Itoa(i))
	}

	acp := utils.RandomACP(attrs)
	//fmt.Println(acp, attrs)
	return &ACJudge{ACS: acp, Props: attrs}
}

func main() {

	contract_name := "Basics"

	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey1 := utils.GetENV("PRIVATE_KEY_1")

	deployTX := utils.Transact(client, privatekey1, big.NewInt(0))

	address, _ := utils.Deploy(client, contract_name, deployTX)

	ctc, _ := contract.NewContract(common.HexToAddress(address.Hex()), client)

	fmt.Println("...........................................................Setup............................................................")

	maabe := rwdabe.NewMAABE()

	const num int = 100               //number of auths
	const times int64 = 5             //test times
	const CTsize1M = int(1024 * 1024) //the msg  iinit set 1M

	attribs := [num][]string{}
	auths := [num]*rwdabe.MAABEAuth{}
	//keys := [n][]*rwdabe.MAABEKey{}
	ksEnc := []*rwdabe.MAABEKey{}
	ksDec := []*rwdabe.MAABEKey{}
	Proofs := []*rwdabe.Proof{}

	// create  authorities, each with two attributes
	for i := 0; i < num; i++ {
		authi := "auth" + strconv.Itoa(i)
		attribs[i] = []string{authi + ":at1"}
		// create three authorities, each with two attributes
		auths[i], _ = maabe.NewMAABEAuth(authi)
	}

	//User Setup...(sk,pk)
	userSk := rwdabe.RandomInt()
	userPk := new(bn128.G1).ScalarMult(auths[0].Maabe.G1, userSk)

	acjudges := make([]*ACJudge, 1)
	acjudges[0] = generateACPStr(num)
	fmt.Println("Access Control Policy:", acjudges[0].ACS)
	//msp, _ := lib.BooleanToMSP(acjudges[0].ACS, false)
	policyStr := ""
	for i := 0; i < num-1; i++ {
		authi := "auth" + strconv.Itoa(i)
		policyStr += authi + ":at1 AND "
	}
	policyStr += "auth" + strconv.Itoa(num-1) + ":at1"
	msp, _ := lib.BooleanToMSP(policyStr, false)

	pks := []*rwdabe.MAABEPubKey{}
	for i := 0; i < num; i++ {
		pks = append(pks, auths[i].Pk)
	}

	fmt.Println("..........................................................Encrypy...........................................................")

	// choose a message , the msg set 5M
	//CTsize := CTsize1M * 1
	//msg := strings.Repeat("a", CTsize)
	msg := "Data sharing in the metaverse with key abuse resistance based on decentralized CP-ABE"
	fmt.Println("The msg is:", msg)
	// encrypt the message with the decryption policy in msp
	ct, err := maabe.ABEEncrypt(msg, msp, pks)
	if err != nil {
		log.Println("加密发生错误:", err)
	}

	fmt.Println("..........................................................Request...........................................................")

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user

	for i := 0; i < num; i++ {
		keys, _ := auths[i].ABEKeyGen(gid, attribs[i][0], userPk)
		ksEnc = append(ksEnc, keys)
		proofs, _ := auths[i].KeyGenPrimeAndGenProofs(keys, userPk)
		Proofs = append(Proofs, proofs)
	}

	fmt.Println("...........................................................Verify...........................................................")

	p1Arr := make([][]contract.BasicsG1Point, 0)
	p2Arr := make([][]contract.BasicsG2Point, 0)
	tmpArr := make([][]*big.Int, 0)
	attrArr := make([]string, 0)

	for i := 0; i < num; i++ {
		intArray := rwdabe.MakeIntArry(Proofs[i])
		newPoint1 := []contract.BasicsG1Point{G1ToPoint(ksEnc[i].Key), G1ToPoint(Proofs[i].Key), G1ToPoint(ksEnc[i].EK2), G1ToPoint(Proofs[i].EK2P)}
		newPoint2 := []contract.BasicsG2Point{G2ToPoint(ksEnc[i].KeyPrime), G2ToPoint(Proofs[i].KeyPrime), G2ToPoint(Proofs[i].G2ToAlpha), G2ToPoint(Proofs[i].G2ToBeta)}
		//offchain Checkkey
		res, _ := maabe.CheckKey(userPk, ksEnc[i], Proofs[i])
		if !res {
			fmt.Println("offchain checkey", res)
		}
		p1Arr = append(p1Arr, newPoint1)
		p2Arr = append(p2Arr, newPoint2)
		tmpArr = append(tmpArr, intArray)
		attrArr = append(attrArr, ksEnc[i].Attrib)

	}
	//on chain CheckKey
	autht1 := utils.Transact(client, privatekey1, big.NewInt(0))
	// fmt.Println(p1Arr)
	tx3, _ := ctc.Checkkeyp(autht1, p1Arr, p2Arr, tmpArr, gid, attrArr, G1ToPoint(userPk)) //checkkey on-chain
	receipt3, _ := bind.WaitMined(context.Background(), client, tx3)
	fmt.Printf("Checkkeyp Gas used: %d\n", receipt3.GasUsed)

	//on chain CheckKey
	autht2 := utils.Transact(client, privatekey1, big.NewInt(0))
	tx4, _ := ctc.Checkkey(autht2, p1Arr, p2Arr, tmpArr, gid, attrArr, G1ToPoint(userPk)) //checkkey on-chain
	receipt4, _ := bind.WaitMined(context.Background(), client, tx4)
	fmt.Printf("Checkkey Gas used: %d\n", receipt4.GasUsed)
	Checkkeyres, _ := ctc.CheckkeyRes(&bind.CallOpts{})
	fmt.Printf("Checkkey Checkkeyres used: %d\n", Checkkeyres)

	//judgeAttrs
	for _, acjudge := range acjudges {
		auth2 := utils.Transact(client, privatekey1, big.NewInt(0))
		tx1, _ := ctc.Validate(auth2, acjudge.Props, acjudge.ACS)
		receipt1, _ := bind.WaitMined(context.Background(), client, tx1)
		fmt.Printf("attribute number %d, Validate ACP Gas used: %d\n", num, receipt1.GasUsed)
	}

	fmt.Println("...........................................................Access...........................................................")

	for i := 0; i < num; i++ {
		key := auths[i].GetKey(ksEnc[i], userSk)
		ksDec = append(ksDec, key)
	}

	// user tries to decrypt with different key combos
	// try to decrypt all messages
	msg1, _ := maabe.ABEDecrypt(ct, ksDec)
	fmt.Println("Decrypt msg is:", msg1)

	fmt.Println("Decrypt Result is:", msg1 == msg)

}
