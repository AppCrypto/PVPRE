package pre

import (
	"TestUmbral/aead"
	"TestUmbral/ukem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bn128 "github.com/fentec-project/bn256"
)

type C struct {
	Capsule       *ukem.Capsule
	EncData       []byte
	Nonec         []byte
	AsspciateData []byte
}

type Cp struct {
	Cfrag         []*ukem.CFrag
	EncData       []byte
	Nonec         []byte
	AsspciateData []byte
}

type Pi struct {
	E2  *bn128.G1
	V2  *bn128.G1
	U2  *bn128.G1
	U1  *bn128.G1
	Z1  *big.Int
	Z2  *big.Int
	Rou *big.Int
	Aux *bn128.G1
}

func KeyGen(par *ukem.Params) (*bn128.G1, *big.Int, *bn128.G1, *big.Int, []*bn128.G1, []*big.Int) {
	ska, _ := rand.Int(rand.Reader, par.Q)
	skb, _ := rand.Int(rand.Reader, par.Q)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	// 公钥作为代理的标识符，私钥没有用到
	PKs := make([]*bn128.G1, par.N)
	SKs := make([]*big.Int, par.N)
	for i := 0; i < par.N; i++ {
		SKs[i], _ = rand.Int(rand.Reader, par.Q)
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}
	return pka, ska, pkb, skb, PKs, SKs
}

func Encrypt(par *ukem.Params, pka *bn128.G1, M []byte) *C {
	K, capsule := ukem.Encapsualate(par, pka)
	associatedData := []byte("This is associated data.")
	c, nonce, _ := aead.AESGCMEncrypt(K, M, associatedData)
	Cip := &C{
		Capsule:       capsule,
		EncData:       c,
		Nonec:         nonce,
		AsspciateData: associatedData,
	}
	return Cip
}

func Decrypt(par *ukem.Params, ska *big.Int, c *C) []byte {
	K, _ := ukem.Decapsulate(par, ska, c.Capsule)
	M, _ := aead.AESGCMDecrypt(K, c.EncData, c.Nonec, c.AsspciateData)
	return M
}

func ReKeyGen(par *ukem.Params, ska *big.Int, pka, pkb *bn128.G1) []*ukem.KFrag {
	return ukem.ReKeyGen(par, ska, pka, pkb)
}

func H(par *ukem.Params, E, E1, E2, V, V1, V2, U, U1, U2, aux *bn128.G1) *big.Int {
	EBytes := E.Marshal()
	E1Bytes := E1.Marshal()
	E2Bytes := E2.Marshal()
	VBytes := V.Marshal()
	V1Bytes := V1.Marshal()
	V2Bytes := V2.Marshal()
	UBytes := U.Marshal()
	U1Bytes := U1.Marshal()
	U2Bytes := U2.Marshal()
	auxBytes := aux.Marshal()

	var data []byte
	data = append(data, EBytes...)
	data = append(data, E1Bytes...)
	data = append(data, E2Bytes...)
	data = append(data, VBytes...)
	data = append(data, V1Bytes...)
	data = append(data, V2Bytes...)
	data = append(data, UBytes...)
	data = append(data, U1Bytes...)
	data = append(data, U2Bytes...)
	data = append(data, auxBytes...)

	hash := sha256.New()
	hash.Write(data)
	hashBytes := hash.Sum(nil)

	hashInt := new(big.Int).SetBytes(hashBytes)
	hashInt.Mod(hashInt, par.Q)
	return hashInt
}

func ReEncrypt(par *ukem.Params, kFrag []*ukem.KFrag, c *C, PKs []*bn128.G1) (*Cp, []*Pi) {
	cFrag := ukem.ReEncapsulate(par, kFrag, c.Capsule)
	Cipp := &Cp{
		Cfrag:         cFrag,
		EncData:       c.EncData,
		Nonec:         c.Nonec,
		AsspciateData: c.AsspciateData,
	}
	// 产生关于每个cFrag的证明
	pi := make([]*Pi, par.N)
	for i := 0; i < par.N; i++ {
		tao, _ := rand.Int(rand.Reader, par.Q)
		E2 := new(bn128.G1).ScalarMult(c.Capsule.E, tao)
		V2 := new(bn128.G1).ScalarMult(c.Capsule.V, tao)
		U2 := new(bn128.G1).ScalarMult(par.U, tao)
		h := H(par, c.Capsule.E, cFrag[i].E1, E2, c.Capsule.V, cFrag[i].V1, V2, par.U, kFrag[i].U1, U2, PKs[i])
		temp := new(big.Int).Mul(h, kFrag[i].Rk)
		rou := new(big.Int).Add(tao, temp)
		pi[i] = &Pi{
			E2:  E2,
			V2:  V2,
			U2:  U2,
			U1:  kFrag[i].U1,
			Z1:  kFrag[i].Z1,
			Z2:  kFrag[i].Z2,
			Rou: rou,
			Aux: PKs[i],
		}
	}
	return Cipp, pi
}

func ReEncVerify(par *ukem.Params, capsule *ukem.Capsule, cFrag []*ukem.CFrag, pi []*Pi) {
	for i := 0; i < par.N; i++ {
		h := H(par, capsule.E, cFrag[i].E1, pi[i].E2, capsule.V, cFrag[i].V1, pi[i].V2, par.U, pi[i].U1, pi[i].U2, pi[i].Aux)
		l1 := new(bn128.G1).ScalarMult(capsule.E, pi[i].Rou)
		temp1 := new(bn128.G1).ScalarMult(cFrag[i].E1, h)
		r1 := new(bn128.G1).Add(pi[i].E2, temp1)
		l2 := new(bn128.G1).ScalarMult(capsule.V, pi[i].Rou)
		temp2 := new(bn128.G1).ScalarMult(cFrag[i].V1, h)
		r2 := new(bn128.G1).Add(pi[i].V2, temp2)
		l3 := new(bn128.G1).ScalarMult(par.U, pi[i].Rou)
		temp3 := new(bn128.G1).ScalarMult(pi[i].U1, h)
		r3 := new(bn128.G1).Add(pi[i].U2, temp3)
		if l1.String() != r1.String() || l2.String() != r2.String() || l3.String() != r3.String() {
			fmt.Printf("第 %v 个 cFrag 没有通过验证\n", i+1)
		}
	}
	// fmt.Printf("All cFrags pass the verification\n")
}

func DecryptFrags(par *ukem.Params, skb *big.Int, pkb, pka *bn128.G1, cp *Cp, lambda []*big.Int) []byte {
	K := ukem.DecapsulateFrags(par, skb, pkb, pka, cp.Cfrag, lambda)
	M, _ := aead.AESGCMDecrypt(K, cp.EncData, cp.Nonec, cp.AsspciateData)
	return M
}
