package main

import (
	"basics/crypto/rwdabe"
	"fmt"
	"strconv"
	"strings"
	"time"

	lib "github.com/fentec-project/gofe/abe"
)

func main() {

	maabe := rwdabe.NewMAABE()

	const num int = 10                //number of auths
	const times int64 = 5             //test times
	const CTsize1M = int(1024 * 1024) //the msg  iinit set 1M

	attribs := [num][]string{}
	auths := [num]*rwdabe.MAABEAuth{}
	//keys := [n][]*rwdabe.MAABEKey{}
	ks1 := []*rwdabe.MAABEKey{} // ok

	for i := 0; i < num; i++ {
		authi := "auth" + strconv.Itoa(i)
		attribs[i] = []string{authi + ":at1"}
		// create three authorities, each with two attributes
		auths[i], _ = maabe.NewMAABEAuth(authi)
	}

	// create a msp struct out of the boolean formula
	policyStr := ""
	for i := 0; i < num-1; i++ {
		authi := "auth" + strconv.Itoa(i)
		policyStr += authi + ":at1 AND "
	}
	policyStr += "auth" + strconv.Itoa(num-1) + ":at1"
	//fmt.Println(policyStr)
	//msp, err := abe.BooleanToMSP("auth1:at1 AND auth2:at1 AND auth3:at1 AND auth4:at1", false)

	// define the set of all public keys we use
	pks := []*rwdabe.MAABEPubKey{}
	for i := 0; i < num; i++ {
		pks = append(pks, auths[i].Pk)
	}
	msp, _ := lib.BooleanToMSP(policyStr, false)

	startts := time.Now().UnixNano() / 1e3
	endts := time.Now().UnixNano() / 1e3
	var ct10 *rwdabe.MAABECipher

	for i := 1; i < num+1; i++ {
		CTsize := CTsize1M * 10 * i
		byte2String := strings.Repeat("a", CTsize) //1M
		startts = time.Now().UnixNano() / 1e3
		for i := 0; i < int(times); i++ {
			//var key []*abe.MAABEKey
			ct10, _ = maabe.ABEEncrypt(byte2String, msp, pks)
		}
		endts = time.Now().UnixNano() / 1e3
		fmt.Printf("%d nodes encrypt time cost: %v ms ,msg size:%dMB\n", num, (endts-startts)/times/1000, CTsize/1024/1024)

	}

	gid := "gid1"

	attribstest := []string{"auth1:at1"}
	startts = time.Now().UnixNano() / 1e3
	//var key []*abe.MAABEKey
	for i := 0; i < int(times); i++ {
		//var key []*abe.MAABEKey
		_, _ = auths[0].ABEKeyGen(gid, attribstest[0])
	}
	endts = time.Now().UnixNano() / 1e3
	fmt.Printf("%d nodes keygen time cost: %v μs \n", num, 2*(endts-startts)/times) //*2 due to LW CP-ABE

	for i := 0; i < num; i++ {
		keys, _ := auths[i].ABEKeyGen(gid, attribs[i][0])
		ks1 = append(ks1, keys)
	}

	for i := 1; i < num+1; i++ {
		CTsize := CTsize1M * 10 * i
		byte2String := strings.Repeat("a", CTsize) //1M
		ct10, _ = maabe.ABEEncrypt(byte2String, msp, pks)
		startts = time.Now().UnixNano() / 1e3
		for i := 0; i < int(times); i++ {
			//var key []*abe.MAABEKey
			_, _ = maabe.ABEDecrypt(ct10, ks1)
		}
		endts = time.Now().UnixNano() / 1e3
		//fmt.Printf("%d nodes encrypt time cost: %v ms and msg size:%dMB\n", num, (endts-startts)/times/1000, CTsize/1024/1024)
		fmt.Printf("%d nodes decrypt time cost: %v ms and msg size:%dMB\n", num, (endts-startts)/times/1000, CTsize/1024/1024)
	}

}
