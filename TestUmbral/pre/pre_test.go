package pre

import (
	"TestUmbral/ukem"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestEncDec(t *testing.T) {
	n, threshold := 5, 3
	par := ukem.Setup(n, threshold)
	pka, ska, _, _, _, _ := KeyGen(par)
	M := []byte("Test message for encryption.")
	C := Encrypt(par, pka, M)

	DecC := Decrypt(par, ska, C)
	// Verify the decrypted message matches the original message
	if string(DecC) != string(M) {
		t.Errorf("Decrypted message does not match the original message")
	}
}

func TestReEncrypt(t *testing.T) {
	n := 80
	threshold := n/2 + 1
	fmt.Println("t = ", threshold)
	par := ukem.Setup(n, threshold)
	pka, ska, pkb, skb, PKs, _ := KeyGen(par)
	// M := []byte("Test message for encryption.")

	// 生成 size MB 的随机数据
	size := 5
	M := make([]byte, size*1024*1024)
	_, err := rand.Read(M) // 读取随机数据填充到M
	if err != nil {
		fmt.Println("Error:", err)
	}

	numRuns := 100 //重复执行次数
	var totalDuration time.Duration

	// 执行多次加密，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = Encrypt(par, pka, M)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d MB size : average encryption time over %d runs: %s\n", size, numRuns, averageDuration)

	// Encrypt data
	C := Encrypt(par, pka, M)

	// 执行多次重加密密钥生成算法，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = ReKeyGen(par, ska, pka, pkb)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReKeyGen time over %d runs: %s\n", par.N, numRuns, averageDuration)

	// Generate re-encryption keys
	kFrag := ReKeyGen(par, ska, pka, pkb)

	// 多次执行重加密过程
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = ReEncrypt(par, kFrag, C, PKs)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReEncrypt time over %d runs: %s\n", par.N, numRuns, averageDuration)

	// Re-encrypt C
	Cp, pi := ReEncrypt(par, kFrag, C, PKs)

	// 多次执行重加密验证过程
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	ReEncVerify(par, C.Capsule, Cp.Cfrag, pi)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReEncVerify time over %d runs: %s\n", par.N, numRuns, averageDuration)

	// Verify the re-encryption
	ReEncVerify(par, C.Capsule, Cp.Cfrag, pi)

	lambda, _ := ukem.PrecomputeLagrangeCoefficients(par, skb, pkb, pka, Cp.Cfrag)

	// 多次执行解密过程
	startTime := time.Now()
	for i := 0; i < numRuns; i++ {
		_ = DecryptFrags(par, skb, pkb, pka, Cp, lambda)
	}
	endTime := time.Now()
	totalDuration = endTime.Sub(startTime)

	// 计算平均时间
	averageDuration := totalDuration / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("%d proxies : average DecryptFrags time over %d runs: %s\n", par.N, numRuns, averageDuration)

	// Decrypt the re-encrypted data
	DecCp := DecryptFrags(par, skb, pkb, pka, Cp, lambda)

	// Verify the decrypted message matches the original message
	if string(DecCp) != string(M) {
		t.Errorf("Re-encrypted message does not match the original message.")
	} else {
		fmt.Printf("Success!\n")
	}
}
