package crypto

import (
	"basics/crypto/lwdabe"
	//"basics/crypto/lwdabe"
	"crypto/rand"
	"fmt"
	bn128 "github.com/fentec-project/bn256"
	"math/big"
	"testing"
	"time"
)

func TestOp(t *testing.T) {
	a := lwdabe.NewMAABE()
	//var tmpGT *bn256.GT
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)

	startts := time.Now().UnixNano()
	for i := 0; i < 1000; i++ {
		_ = new(bn128.G1).ScalarMult(a.G1, serialNumber)
	}
	endts := time.Now().UnixNano()
	fmt.Printf("G1 Exp time cost %v ns\n", (endts-startts)/1000)

	startts = time.Now().UnixNano()
	for i := 0; i < 1000; i++ {
		_ = new(bn128.G2).ScalarMult(a.G2, serialNumber)
	}
	endts = time.Now().UnixNano()
	fmt.Printf("G2 Exp time cost %v ns\n", (endts-startts)/1000)

	startts = time.Now().UnixNano()
	for i := 0; i < 1000; i++ {
		_ = new(bn128.GT).ScalarMult(a.Gt, serialNumber)
	}
	endts = time.Now().UnixNano()
	fmt.Printf("GT Exp time cost %v ns\n", (endts-startts)/1000)

	startts = time.Now().UnixNano()
	for i := 0; i < 1000; i++ {
		bn128.Pair(a.G1, a.G2)
	}
	endts = time.Now().UnixNano()
	fmt.Printf("Pair time cost %v ns\n", (endts-startts)/1000)

}
