package preiomt

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"time"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvpre/bn128"

	"github.com/stretchr/testify/assert"
)

func randomBigInt() *big.Int {
	n, _ := rand.Int(rand.Reader, bn128.Order)
	return n
}

func TestAPRE(t *testing.T) {
	// 1 Setup
	para := Setup()

	// 2.Generate keys for sender (i) and receiver (j)
	// Private keys

	IDi := []byte("123456789")
	ski := para.H(IDi)
	ski.Mod(ski, bn128.Order)
	pki := new(bn128.G1).ScalarMult(para.G, ski)

	IDj := []byte("987654321")
	skj := para.H(IDj)
	skj.Mod(skj, bn128.Order)
	pkj := new(bn128.G2).ScalarMult(para.G1, skj)

	// Generate a random message in GT
	smg1 := randomBigInt()
	mg1 := new(bn128.G1).ScalarBaseMult(smg1)
	smg2 := randomBigInt()
	mg2 := new(bn128.G2).ScalarBaseMult(smg2)

	m := bn128.Pair(mg1, mg2)

	// Encrypt the message using sender's public key
	C := Encrypt(para, pki, m)

	// Generate re-encryption key from sender to receiver
	rk := ReKeyGen(para, ski, pkj)

	// Perform re-encryption
	Cp := ReEncrypt(para, C, rk)

	// Receiver decrypts the re-encrypted ciphertext
	M := Dec(para, Cp, skj)

	// Mo := Decrypt(para, ski, C)

	// 8. Verify the decrypted message matches the original message
	assert.Equal(t, m.String(), M.String(), "Decrypted message does not match the original")

	numRuns := 100 //重复执行次数
	var totalDuration time.Duration

	// 执行多次加密，计算平均时间  大约2ms
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = Encrypt(para, pki, m)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("Average encryption time over %d runs: %s\n", numRuns, averageDuration)

	// // 执行重加密密钥生成算法，计算平均时间  大约1.1ms
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = ReKeyGen(para, ski, pkj)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("Average ReKeyGen time over %d runs: %s\n", numRuns, averageDuration)

	// 执行重加密算法，计算平均时间  大约1.18ms
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = ReEncrypt(para, C, rk)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("Average ReEnc time over %d runs: %s\n", numRuns, averageDuration)

	// 执行解密算法，计算平均时间  大约2ms
	startTime := time.Now()
	for i := 0; i < numRuns; i++ {
		_ = Dec(para, Cp, skj)
	}
	endTime := time.Now()
	totalDuration = endTime.Sub(startTime)

	// 计算平均时间
	averageDuration := totalDuration / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("Average Dec1 time over %d runs: %s\n", numRuns, averageDuration)

}
