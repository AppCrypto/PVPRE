package pvpre

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"pvpre/crypto/aes"
	"pvpre/crypto/dhpvss"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvpre/bn128"

	"golang.org/x/crypto/hkdf"
	// bn128 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// KDF:
type KDFFunc func(*bn128.G1) []byte

// C:
type C struct {
	C1 []byte
	C2 *bn128.G1
}

// C':
type Cp struct {
	C1  []byte
	C2p []*bn128.G1
}

// KDF 的实现：使用HKDF生成固定长度的对称密钥
func KDFfunc(input *bn128.G1, l int) []byte {
	// 将G1元素转换为字节数组
	inputBytes := input.Marshal()

	// 使用 HKDF 从输入生成一个 AES 密钥
	salt := make([]byte, 32)             // 盐值可以根据需要更改为固定值或随机生成
	info := []byte("AES Key Derivation") // 可选，额外的信息用于派生密钥

	// 使用HKDF生成密钥
	hkdf := hkdf.New(sha256.New, inputBytes, salt, info)

	// 从HKDF获取固定长度的密钥
	key := make([]byte, l/8) //l 为密钥长度（位），转为字节
	_, err := hkdf.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

type PrePar struct {
	Par *dhpvss.Dhpvsspar
	KDF KDFFunc
}

func PRESetup(n, t, l int) (*PrePar, *big.Int, error) {
	par, s, err := dhpvss.DHPVSSSetup(n, t, l)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating GsSetup: %v", err)
	}
	KDF := func(input *bn128.G1) []byte {
		return KDFfunc(input, l)
	}

	Para := &PrePar{
		Par: par,
		KDF: KDF,
	}
	return Para, s, nil
}

func PREKeyGen(Para *PrePar) (*bn128.G1, *big.Int, *bn128.G1, *big.Int, []*bn128.G1, []*big.Int) {
	ska, _ := rand.Int(rand.Reader, Para.Par.PP.P)
	skb, _ := rand.Int(rand.Reader, Para.Par.PP.P)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, Para.Par.PP.N)
	SKs := make([]*big.Int, Para.Par.PP.N)
	for i := 0; i < Para.Par.PP.N; i++ {
		SKs[i], _ = rand.Int(rand.Reader, Para.Par.PP.P)
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}
	return pka, ska, pkb, skb, PKs, SKs
}

func PREReKeyGen(Para *PrePar, pkb *bn128.G1, ska *big.Int, pka *bn128.G1, PKs []*bn128.G1, s *big.Int) ([]*bn128.G1, *dhpvss.DLEQProof) {
	ckFrag, pi_sh := dhpvss.DHPVSSShare(Para.Par, pkb, pka, ska, PKs, s)
	return ckFrag, pi_sh
}

func PREReKeyVerify(Para *PrePar, pka *bn128.G1, pkb *bn128.G1, ckFrag []*bn128.G1, PKs []*bn128.G1, pi_sh *dhpvss.DLEQProof) bool {
	reKeyValidity := dhpvss.DHPVSSVerify(Para.Par, pka, pkb, ckFrag, PKs, pi_sh)
	return reKeyValidity
}

func PREEnc2(Para *PrePar, pka *bn128.G1, M []byte, s *big.Int) *C {
	S := new(bn128.G1).ScalarBaseMult(s)
	K := Para.KDF(S)
	// fmt.Println("密钥长度为：", len(K))
	C1, err := aes.AESEncrypt(M, K)
	if err != nil {
		fmt.Println("Error during encryption:", err)
	}
	C2 := new(bn128.G1).ScalarMult(pka, s)
	C := &C{C1: C1, C2: C2}
	return C
}

func PREReEnc(Para *PrePar, pka *bn128.G1, ckFrag []*bn128.G1, PKs []*bn128.G1, SKs []*big.Int, C *C) (*Cp, *dhpvss.DLEQProofs) {
	C2p, pi_re := dhpvss.DHPVSSPreRecon(Para.Par, pka, PKs, SKs, ckFrag)
	Cp := &Cp{C1: C.C1, C2p: C2p}
	return Cp, pi_re
}

func PREReEncVerify(Para *PrePar, ckFrag []*bn128.G1, Cp *Cp, pi_re *dhpvss.DLEQProofs, PKs []*bn128.G1, pka *bn128.G1) bool {
	reEncValidity := dhpvss.DHPVSSVerifyDec(Para.Par, pka, PKs, ckFrag, Cp.C2p, pi_re)
	return reEncValidity
}

func PREDec2(Para *PrePar, ska *big.Int, C *C) []byte {
	exp := new(big.Int).ModInverse(ska, Para.Par.PP.P)
	temp := new(bn128.G1).ScalarMult(C.C2, exp)
	K := Para.KDF(temp)
	// fmt.Println("delegator's K:", K)
	M, err := aes.AESDecrypt(C.C1, K)
	if err != nil {
		fmt.Println("Error during decryption:", err)
	}
	return M
}

func PREDec1(Para *PrePar, pka *bn128.G1, skb *big.Int, Cp *Cp, I []int, lambda []*big.Int) []byte {
	PreK := dhpvss.DHPVSSRecon(Para.Par, Cp.C2p, pka, skb, I, lambda)
	K := Para.KDF(PreK)
	// fmt.Println("delegatee's K:", K)
	M, err := aes.AESDecrypt(Cp.C1, K)
	if err != nil {
		fmt.Println("Error during decryption:", err)
	}
	return M
}
