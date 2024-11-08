package main

import (
	"basics/crypto/rwdabe"
	"fmt"
	"time"

	bn128 "github.com/fentec-project/bn256"
)

type Proof1 struct {
	K0  *bn128.G1
	L0  *bn128.G1
	L1  *bn128.G1
	Ki1 *bn128.G1
	Ki2 *bn128.G1
	//g *bn128.G2
}

func CheckKeyGuo(proof *Proof1, n int) (bool, error) {
	maabe := rwdabe.NewMAABE()
	k1 := rwdabe.RandomInt()
	//fmt.Println(k1)
	t := 0
	gaid := new(bn128.G2).ScalarMult(maabe.G2, k1)

	//part2 := new(bn128.G2).ScalarMult(proof.Key2, big.NewInt(1))
	//part2.P.Mul(new(bn128.G2).ScalarMult(proof.Key2, big.NewInt(1)),k1)

	left1 := bn128.Pair(proof.L1, maabe.G2)
	right1 := bn128.Pair(proof.L0, gaid)
	if left1.String() != right1.String() {
		t++ //eq1
	}

	gk := new(bn128.G2).ScalarMult(maabe.G2, k1)
	gaid.Add(gaid, gk)
	left2 := bn128.Pair(proof.K0, gaid)

	tmp := new(bn128.G1).ScalarMult(proof.L0, k1)
	tmp.Add(tmp, proof.L1)
	right2 := new(bn128.GT).Add(bn128.Pair(maabe.G1, gaid), bn128.Pair(tmp, maabe.G2))
	if left2.String() != right2.String() {
		t++ //eq2
	}

	for i := 1; i <= n; i++ {
		tmp := new(bn128.G1).ScalarMult(proof.L0, k1)
		tmp.Add(tmp, proof.L1)
		left3 := new(bn128.GT).Add(bn128.Pair(proof.Ki2, maabe.G2), bn128.Pair(tmp, maabe.G2))

		uaid := new(bn128.G2).ScalarMult(maabe.G2, k1)
		right3 := new(bn128.GT).Add(bn128.Pair(proof.Ki1, maabe.G2), bn128.Pair(proof.Ki1, uaid))
		if left3.String() != right3.String() {
			t++ //eq3
		}
	}

	return true, nil
}

type Proof2 struct {
	Dgid1 *bn128.G1
	Dgid4 *bn128.G1
	Dgid5 *bn128.G2

	//g *bn128.G2
}

func CheckKeyYang(proof *Proof2, n int) (bool, error) {
	t := 0
	maabe := rwdabe.NewMAABE()
	Dgid2 := rwdabe.RandomInt()
	Dgid3 := rwdabe.RandomInt()

	solid := bn128.Pair(proof.Dgid1, maabe.G2)
	for i := 1; i <= n; i++ {
		left1 := bn128.Pair(maabe.G1, proof.Dgid5)

		aj := rwdabe.RandomInt()
		bj := rwdabe.RandomInt()
		rtmp1 := new(bn128.G2).ScalarMult(maabe.G2, aj)
		rtmp2 := new(bn128.G2).ScalarMult(maabe.G2, bj)
		rtmp2 = new(bn128.G2).ScalarMult(rtmp2, Dgid3)
		rtmp1.Add(rtmp1, rtmp2)
		right1 := bn128.Pair(proof.Dgid4, rtmp1)
		if left1.String() != right1.String() {
			t++ //eq3
		}

		ltmp := new(bn128.G2).ScalarMult(maabe.G2, Dgid2)
		ltmp.Add(ltmp, rtmp1)
		left2 := bn128.Pair(proof.Dgid1, ltmp)

		g2tmp := new(bn128.G2).ScalarMult(proof.Dgid5, Dgid2)
		g2tmp.Add(g2tmp, proof.Dgid5)
		right2tmp := solid
		right2 := new(bn128.GT).Add(bn128.Pair(maabe.G1, rtmp1), bn128.Pair(maabe.G1, rtmp2))
		right2.Add(right2tmp, right2)

		if left2.String() != right2.String() {
			t++ //eq3
		}
	}
	return true, nil
}

type Proof3 struct {
	K  *bn128.G1
	L  *bn128.G2
	Lp *bn128.G2
	K1 *bn128.G1
	// *bn128.G2
}

func CheckKeyHan(proof *Proof3, n int) (bool, error) {
	t := 0
	maabe := rwdabe.NewMAABE()
	kp := rwdabe.RandomInt()
	a := rwdabe.RandomInt()
	left1 := bn128.Pair(maabe.G1, proof.Lp)

	tmp1 := new(bn128.G1).ScalarMult(maabe.G1, a)
	//tmp2 := new(bn128.G1).ScalarMult(maabe.G1, kp)

	right1 := bn128.Pair(tmp1, proof.L)

	if left1.String() != right1.String() {
		t++ //eq1
	}

	tmp3 := new(bn128.G2).ScalarMult(maabe.G2, a)
	tmp4 := new(bn128.G2).ScalarMult(maabe.G2, kp)
	tmp3.Add(tmp3, tmp4)
	left2 := bn128.Pair(proof.K, tmp3)

	rtmp := new(bn128.G1).ScalarMult(proof.K1, kp)
	rtmp.Add(rtmp, proof.K1)
	right2 := new(bn128.GT).Add(bn128.Pair(maabe.G1, tmp3), bn128.Pair(rtmp, maabe.G2))

	if left2.String() != right2.String() {
		t++ //eq1
	}

	u := tmp4
	for i := 1; i <= n; i++ {

		rtmp := new(bn128.G1).ScalarMult(proof.K1, kp)
		rtmp.Add(rtmp, proof.K1)

		left3 := new(bn128.GT).Add(bn128.Pair(proof.K1, maabe.G2), bn128.Pair(rtmp, u))

		s := rwdabe.RandomInt()
		stmp := new(bn128.G1).ScalarMult(proof.K1, s)
		right3 := bn128.Pair(stmp, proof.L)
		if left3.String() != right3.String() {
			t++ //eq1
		}
	}

	return true, nil
}

func main() {

	maabe := rwdabe.NewMAABE()

	const times int64 = 10
	const attrs int = 60

	proof1 := Proof1{
		K0:  maabe.G1,
		L0:  maabe.G1,
		L1:  maabe.G1,
		Ki1: maabe.G1,
		Ki2: maabe.G1,
		// g:  new(bn256.G2), // 如果需要可以取消注释
	}

	startts := time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_, _ = CheckKeyGuo(&proof1, attrs)
	}
	endts := time.Now().UnixNano() / 1e3
	fmt.Printf("CheckKeyGuo time cost: %v μs\n", (endts-startts)/times)

	proof2 := Proof2{
		Dgid1: maabe.G1,
		Dgid4: maabe.G1,
		Dgid5: maabe.G2,
		// g:  new(bn256.G2), // 如果需要可以取消注释
	}

	startts = time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_, _ = CheckKeyYang(&proof2, attrs)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("CheckKeyYang time cost: %v μs\n", (endts-startts)/times)

	proof3 := Proof3{
		K:  maabe.G1,
		L:  maabe.G2,
		Lp: maabe.G2,
		K1: maabe.G1,
		// g:  new(bn256.G2), // 如果需要可以取消注释
	}

	startts = time.Now().UnixNano() / 1e3
	for i := 0; i < int(times); i++ {
		_, _ = CheckKeyHan(&proof3, attrs)
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("CheckKeyHan time cost: %v μs\n", (endts-startts)/times)

	gid := "'gid'"
	//attribs1 := []string{"auth1:at1", "auth1:at2"}
	//attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	//attribs4 := []string{"auth4:at1", "auth4:at2"}
	//auth1, _ := maabe.NewMAABEAuth("auth1")
	//auth2, _ := maabe.NewMAABEAuth("auth2")
	auth3, _ := maabe.NewMAABEAuth("auth3")
	//auth4, _ := maabe.NewMAABEAuth("auth4")
	// create a msp struct out of the boolean formula
	//msp, _ := lib.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	userSk := rwdabe.RandomInt()
	userPk := new(bn128.G1).ScalarMult(auth3.Maabe.G1, userSk)
	key31Enc, _ := auth3.ABEKeyGen(gid, attribs3[0], userPk)
	proof, _ := auth3.KeyGenPrimeAndGenProofs(key31Enc, userPk)
	startts1 := time.Now().UnixNano() / 1e3

	for i := 0; i < int(times); i++ {
		hashGID := maabe.HashG1(key31Enc.Gid)
		F_delta := maabe.HashG1(key31Enc.Attrib)
		left3 := new(bn128.GT).Add(bn128.Pair(userPk, proof.G2ToAlpha), bn128.Pair(hashGID, proof.G2ToBeta))
		for i := 0; i < int(attrs); i++ {
			_, _ = maabe.CheckKey(userPk, key31Enc, proof, hashGID, F_delta, left3)
		}
	}
	endts1 := time.Now().UnixNano() / 1e3
	fmt.Printf("Off-chain CheckKey time cost: %v μs\n ", (endts1-startts1)/times)

}
