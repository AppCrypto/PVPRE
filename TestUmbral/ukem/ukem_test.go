package ukem

import (
	"bytes"
	"fmt"

	"math/big"
	"testing"

	bn128 "github.com/fentec-project/bn256"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	// 测试 Setup 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)

	// 确保参数初始化正确
	assert.NotNil(t, params)
	assert.Equal(t, n, params.N)
	assert.Equal(t, threshold, params.T)
	assert.NotNil(t, params.G)
	assert.NotNil(t, params.Q)
	assert.NotNil(t, params.U)
	assert.NotNil(t, params.H2)
	assert.NotNil(t, params.H3)
	assert.NotNil(t, params.H4)
}

func TestKeyGen(t *testing.T) {
	// 测试 KeyGen 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, ska, pkb, skb, PKs, SKs := KeyGen(params)

	// 测试生成的公钥和私钥
	assert.NotNil(t, pka)
	assert.NotNil(t, ska)
	assert.NotNil(t, pkb)
	assert.NotNil(t, skb)
	assert.Len(t, PKs, n)
	assert.Len(t, SKs, n)
}

func TestEncapsulate(t *testing.T) {
	// 测试 Encapsulate 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, _, _, _, _, _ := KeyGen(params)

	K, Capsule := Encapsualate(params, pka)

	// 测试密钥和封装物
	assert.Len(t, K, 32) // K 应该是 256 位（32 字节）
	assert.NotNil(t, Capsule)
	assert.NotNil(t, Capsule.E)
	assert.NotNil(t, Capsule.V)
	assert.NotNil(t, Capsule.s)
}

func TestCheckCapsule(t *testing.T) {
	// 测试 CheckCapsule 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, _, _, _, _, _ := KeyGen(params)

	// 创建封装物
	_, Capsule := Encapsualate(params, pka)

	// 测试封装物检查
	isValid := CheckCapsule(params, Capsule)
	assert.True(t, isValid)

	// 测试无效封装物（修改 Capsule 中的 E）
	Capsule.E = new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	isValid = CheckCapsule(params, Capsule)
	assert.False(t, isValid)
}

func TestDecapsulate(t *testing.T) {
	// 测试 Decapsulate 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, ska, _, _, _, _ := KeyGen(params)

	// 创建封装物
	K, Capsule := Encapsualate(params, pka)

	// 测试解封装
	decapsulatedK, err := Decapsulate(params, ska, Capsule)
	// 比较是否相同
	// 比较是否相同
	if bytes.Equal(decapsulatedK, K) {
		fmt.Println("Success: Encapsulation and decapsulation are correct.")
	} else {
		fmt.Println("Error: Decapsulated key does not match original key.")
	}
	assert.Nil(t, err)
	assert.Len(t, decapsulatedK, 32) // K 应该是 256 位（32 字节）

	// 测试无效的封装物
	Capsule.E = new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	_, err = Decapsulate(params, ska, Capsule)
	assert.NotNil(t, err)
}

func TestReKeyGen(t *testing.T) {
	// 测试 ReKeyGen 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, ska, pkb, _, _, _ := KeyGen(params)

	kFrags := ReKeyGen(params, ska, pka, pkb)

	// 测试密钥碎片生成
	assert.Len(t, kFrags, n)
	for i := 0; i < n; i++ {
		assert.NotNil(t, kFrags[i].Id)
		assert.NotNil(t, kFrags[i].Rk)
		assert.NotNil(t, kFrags[i].X_A)
		assert.NotNil(t, kFrags[i].U1)
		assert.NotNil(t, kFrags[i].Z1)
		assert.NotNil(t, kFrags[i].Z2)
	}
}

func TestReEncapsulate(t *testing.T) {
	// 测试 ReEncapsulate 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, ska, pkb, _, _, _ := KeyGen(params)

	// 创建封装物
	_, Capsule := Encapsualate(params, pka)

	// 生成密钥碎片
	kFrags := ReKeyGen(params, ska, pka, pkb)

	// 测试重新封装
	cFrags := ReEncapsulate(params, kFrags, Capsule)

	// 测试碎片生成
	assert.Len(t, cFrags, n)
	for i := 0; i < n; i++ {
		assert.NotNil(t, cFrags[i].E1)
		assert.NotNil(t, cFrags[i].V1)
		assert.NotNil(t, cFrags[i].Id)
		assert.NotNil(t, cFrags[i].X)
	}
}

func TestDecapsulateFrags(t *testing.T) {
	// 测试 DecapsulateFrags 函数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, ska, pkb, skb, _, _ := KeyGen(params)

	// 创建封装物
	K, Capsule := Encapsualate(params, pka)

	// 生成密钥碎片
	kFrags := ReKeyGen(params, ska, pka, pkb)
	cFrags := ReEncapsulate(params, kFrags, Capsule)

	lambda, _ := PrecomputeLagrangeCoefficients(params, skb, pkb, pka, cFrags)

	// 测试碎片解封装
	K2 := DecapsulateFrags(params, skb, pkb, pka, cFrags, lambda)
	// 比较是否相同

	if bytes.Equal(K2, K) {
		fmt.Println("Success: Encapsulation and decapsulation are correct.")
	} else {
		fmt.Println("Error: Decapsulated key does not match original key.")
	}

	// 测试解封装结果
	assert.Len(t, K2, 32) // K 应该是 256 位（32 字节）
}

func TestEncryptionDecryptionConsistency(t *testing.T) {
	// 测试加密解密一致性

	// 设置参数
	n, threshold := 5, 3
	params := Setup(n, threshold)
	pka, ska, _, _, _, _ := KeyGen(params)

	// 原始明文
	plaintext := []byte("This is a test message!")

	// 加密：封装过程
	K, Capsule := Encapsualate(params, pka)

	// 解密：解封装过程
	decapsulatedK, err := Decapsulate(params, ska, Capsule)
	assert.Nil(t, err)

	// 确保密钥一致
	assert.Equal(t, K, decapsulatedK)

	// 加密明文（使用密钥）
	encMessage, err := encryptWithKey(K, plaintext)
	assert.Nil(t, err)

	// 解密明文（使用解密密钥）
	decMessage, err := decryptWithKey(decapsulatedK, encMessage)
	assert.Nil(t, err)

	// 验证解密后的消息是否与原始明文相同
	assert.True(t, bytes.Equal(plaintext, decMessage))
}

// 使用密钥加密
func encryptWithKey(key []byte, plaintext []byte) ([]byte, error) {
	// 使用简单的加密算法（例如 XOR）来模拟加密操作
	encMessage := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		encMessage[i] = plaintext[i] ^ key[i%len(key)]
	}
	return encMessage, nil
}

// 使用密钥解密
func decryptWithKey(key []byte, ciphertext []byte) ([]byte, error) {
	// 解密操作：与加密操作对称
	return encryptWithKey(key, ciphertext)
}
