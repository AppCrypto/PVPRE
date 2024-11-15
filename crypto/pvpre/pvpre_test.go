package pvpre_test

import (
	"crypto/rand"
	"fmt"
	"pvpre/crypto/gss"
	"pvpre/crypto/pvpre"
	"testing"
	"time"
)

func TestPVPRE(t *testing.T) {
	// 初始化PRE协议的参数
	n, l := 100, 256
	threshold := n/2 + 1
	Para, s, err := pvpre.PRESetup(n, threshold, l)
	if err != nil {
		t.Fatalf("Error during PRESetup: %v", err)
	}

	// 生成密钥对
	pka, ska, pkb, skb, PKs, SKs := pvpre.PREKeyGen(Para)

	// 加密
	// 生成 size MB 的随机数据
	size := 5
	M := make([]byte, size*1024*1024)
	_, err = rand.Read(M)
	if err != nil {
		fmt.Println("Error generating random data:", err)
		return
	}
	// M := []byte("这是一个测试消息，用来测试解密结果是否匹配。")
	// fmt.Println("Plaintext M:", M)

	numRuns := 100 //重复执行次数
	var totalDuration time.Duration

	// 执行多次加密，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = pvpre.PREEnc2(Para, pka, M, s)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d MB size : average encryption time over %d runs: %s\n", size, numRuns, averageDuration)

	C := pvpre.PREEnc2(Para, pka, M, s)

	// PREEnc2Time := endTime.Sub(startTime)
	// fmt.Println("Encrypt time cost:", PREEnc2Time)

	// 打印加密结果
	// fmt.Println("Encrypted C1:", C.C1)
	// fmt.Println("Encrypted C2:", C.C2)

	// 执行多次生成重加密密钥过程，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = pvpre.PREReKeyGen(Para, pkb, ska, pka, PKs, s)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReKeyGen time over %d runs: %s\n", Para.Par.PP.N, numRuns, averageDuration)

	// 生成重加密密钥
	ckFrag, pi_sh := pvpre.PREReKeyGen(Para, pkb, ska, pka, PKs, s)

	// 执行多次生成重加密密钥验证过程，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = pvpre.PREReKeyVerify(Para, pka, pkb, ckFrag, PKs, pi_sh)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReKeyVerify offChain time over %d runs: %s\n", Para.Par.PP.N, numRuns, averageDuration)

	// 验证重加密密钥
	reKeyValidity := pvpre.PREReKeyVerify(Para, pka, pkb, ckFrag, PKs, pi_sh)
	if !reKeyValidity {
		t.Fatalf("ReKey failed validation!")
	}

	// 执行多次生成重加密过程，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = pvpre.PREReEnc(Para, pka, ckFrag, PKs, SKs, C)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReEncryption time over %d runs: %s\n", Para.Par.PP.N, numRuns, averageDuration)

	// 重加密
	Cp, pi_re := pvpre.PREReEnc(Para, pka, ckFrag, PKs, SKs, C)
	// 打印重加密后的结果
	// fmt.Println("ReEncrypted C1:", Cp.C1)
	// fmt.Println("ReEncrypted C2p:", Cp.C2p)

	// 验证重加密密文

	// 执行多次生成重加密验证过程，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_ = pvpre.PREReEncVerify(Para, ckFrag, Cp, pi_re, PKs, pka)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("%d proxies : average ReEncryptVerify offChain time over %d runs: %s\n", Para.Par.PP.N, numRuns, averageDuration)

	reEncValidity := pvpre.PREReEncVerify(Para, ckFrag, Cp, pi_re, PKs, pka)
	if !reEncValidity {
		t.Fatalf("ReEncryption failed validation!")
	}

	// delegator解密原始密文
	M_dec2 := pvpre.PREDec2(Para, ska, C)
	// fmt.Println("Decrypted Message by delegator:", M_dec2)

	// delegatee解密重加密密文
	// 取0前t个份额进行恢复
	I := make([]int, Para.Par.PP.T)
	for i := 0; i < Para.Par.PP.T; i++ {
		I[i] = i + 1
	}

	lambda, _ := gss.PrecomputeLagrangeCoefficients(Para.Par.PP, I)

	// 执行多次重加密密文解密过程，计算平均时间
	startTime := time.Now()
	for i := 0; i < numRuns; i++ {
		_ = pvpre.PREDec1(Para, pka, skb, Cp, I, lambda)
	}
	endTime := time.Now()
	totalDuration = endTime.Sub(startTime)

	// 计算平均时间
	averageDuration := totalDuration / time.Duration(numRuns)

	// 输出平均加密时间
	fmt.Printf("%d proxies : average PREDec1 time over %d runs: %s\n", Para.Par.PP.N, numRuns, averageDuration)

	M_dec1 := pvpre.PREDec1(Para, pka, skb, Cp, I, lambda)
	// fmt.Println("Decrypted Message by delegatee:", M_dec1)

	// 验证解密
	if string(M_dec1) == string(M) && string(M_dec2) == string(M) {
		t.Log("Test passed: message was correctly encrypted, re-encrypted, and decrypted.")
	} else {
		t.Fatalf("Test failed: decrypted message does not match the original message.")
	}
	// 验证delegator的解密
	// if string(M_dec2) == string(M) {
	// 	// fmt.Print("The original ciphertext is correctly decrypted by degetagor.\n")
	// 	t.Log("Test passed: the original ciphertext is correctly decrypted by degetagor.")
	// }

	// // 验证delegatee的解密
	// if string(M_dec1) == string(M) {
	// 	// fmt.Print("The re-encryption ciphertext is correctly decrypted by delegatee.\n")
	// 	t.Log("Test passed: the re-encryption ciphertext is correctly decrypted by delegatee.")
	// }

}
