package gss_test

import (
	"crypto/rand"
	"testing"

	// "time"

	"pvpre/crypto/gss"

	bn128 "github.com/fentec-project/bn256"
	// bn128 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// 测试公共参数生成
func TestGsStup(t *testing.T) {
	n, threshold := 5, 3
	pp, err := gss.GsSetup(n, threshold)
	if err != nil {
		t.Fatalf("Error during setup: %v", err)
	}

	if pp.G == nil || pp.P == nil {
		t.Fatal("Failed to initialize group generator or group order")
	}

	if pp.N != n || pp.T != threshold {
		t.Fatal("Public parameters n or t do not match the input values")
	}
}

// 测试秘密分享生成
func TestGsShare(t *testing.T) {
	n, threshold := 10, 6
	pp, err := gss.GsSetup(n, threshold)
	if err != nil {
		t.Fatalf("Error during setup: %v", err)
	}

	// 生成随机秘密
	secret, _ := rand.Int(rand.Reader, pp.P)

	// numRuns := 100 //重复执行次数
	// var totalDuration time.Duration
	// // 执行多次加密，计算平均时间
	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = gss.GsShare(pp, secret)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// // 计算平均时间
	// averageDuration := totalDuration / time.Duration(numRuns)

	// // 输出平均加密时间
	// fmt.Printf("Average GsShare time over %d runs: %s\n", numRuns, averageDuration)

	shares, err := gss.GsShare(pp, secret)
	if err != nil {
		t.Fatalf("Error generating shares: %v", err)
	}
	if len(shares) != n {
		t.Fatalf("Expected %d shares, got %d", n, len(shares))
	}

	// 验证每个分享是否为群 G 的元素
	for _, share := range shares {
		if share == nil {
			t.Fatal("One of the shares is nil")
		}
	}
}

// 测试秘密恢复
func TestGSRecon(t *testing.T) {
	n, threshold := 10, 6
	pp, err := gss.GsSetup(n, threshold)
	if err != nil {
		t.Fatalf("Error during setup: %v", err)
	}

	// 生成随机秘密
	secret, _ := rand.Int(rand.Reader, pp.P)
	shares, err := gss.GsShare(pp, secret)
	if err != nil {
		t.Fatalf("Error generating shares: %v", err)
	}

	// 选择任意 t 个分享进行恢复
	// 取0前t个份额进行恢复
	I := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = i + 1
	}
	// selectedShares := []*bn128.G1{shares[0], shares[1], shares[2]}

	recoveredSecret, err := gss.GsRecon(pp, I, shares)
	if err != nil {
		t.Fatalf("Error reconstructing secret: %v", err)
	}

	// // 将秘密转化为 G 上的元素，验证恢复的秘密是否匹配
	expectedSecret := new(bn128.G1).ScalarBaseMult(secret)
	if recoveredSecret.String() != expectedSecret.String() {
		t.Fatal("Recovered secret does not match the original secret")
	}
}
