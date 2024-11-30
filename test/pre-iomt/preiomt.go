package preiomt

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	bn128 "github.com/fentec-project/bn256"
)

type HFunc func([]byte) *big.Int

type Param struct {
	G  *bn128.G1 //G1的生成元
	G1 *bn128.G2 //G2的生成元
	H  HFunc
}

type C struct {
	C1 *bn128.G1
	C2 *bn128.GT
	C3 *big.Int
}

type RK struct {
	Rk1 *bn128.G2
	Rk2 *bn128.G2
	Rk3 *big.Int
}

type Cp struct {
	W1 *bn128.G1
	W2 *bn128.GT
	W3 *bn128.G2
	W4 *big.Int
}

func Hfunc(input []byte) *big.Int {
	hash := sha256.Sum256(input)

	result := new(big.Int).SetBytes(hash[:])
	result.Mod(result, bn128.Order)

	return result
}

func Setup() *Param {
	g := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	g1 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	H := func(input []byte) *big.Int {
		return Hfunc(input)
	}

	param := &Param{
		G:  g,
		G1: g1,
		H:  H,
	}
	return param
}

func Encrypt(param *Param, pki *bn128.G1, m *bn128.GT) *C {
	ri, _ := rand.Int(rand.Reader, bn128.Order)
	c1 := new(bn128.G1).ScalarMult(param.G, ri)
	eg1pki := bn128.Pair(pki, param.G1)
	temp1 := new(bn128.GT).ScalarMult(eg1pki, ri)
	c2 := new(bn128.GT).Add(m, temp1)
	hc1 := param.H(c1.Marshal())
	c1c2 := append(c1.Marshal(), c2.Marshal()...)
	hc1c2 := param.H(c1c2)
	c3 := param.H(append(hc1.Bytes(), hc1c2.Bytes()...))

	c := &C{
		C1: c1,
		C2: c2,
		C3: c3,
	}
	return c
}

func Decrypt(param *Param, ski *big.Int, c *C) *bn128.GT {
	g1h := new(bn128.G2).ScalarMult(param.G1, ski)
	temp := bn128.Pair(c.C1, g1h)
	temp.Neg(temp)
	m := new(bn128.GT).Add(c.C2, temp)
	return m
}

func ReKeyGen(param *Param, ski *big.Int, pkj *bn128.G2) *RK {
	rj, _ := rand.Int(rand.Reader, bn128.Order)
	rk1 := new(bn128.G2).ScalarMult(param.G1, rj)
	skin := new(big.Int).Neg(ski)
	skin.Mod(skin, bn128.Order)
	g1skin := new(bn128.G2).ScalarMult(param.G1, skin)
	pkjrj := new(bn128.G2).ScalarMult(pkj, rj)
	rk2 := new(bn128.G2).Add(g1skin, pkjrj)
	rk1byte := rk1.Marshal()
	rk2byte := rk2.Marshal()
	hrk1 := param.H(rk1byte)
	rk1rk2 := append(rk1byte, rk2byte...)
	hrk1rk2 := param.H(rk1rk2)
	rk3 := param.H(append(hrk1.Bytes(), hrk1rk2.Bytes()...))

	rk := &RK{
		Rk1: rk1,
		Rk2: rk2,
		Rk3: rk3,
	}
	return rk
}

func ReEncrypt(param *Param, c *C, rk *RK) *Cp {
	w1 := c.C1
	temp := bn128.Pair(c.C1, rk.Rk2)
	w2 := new(bn128.GT).Add(c.C2, temp)
	w3 := rk.Rk1
	w1byte := w1.Marshal()
	w2byte := w2.Marshal()
	w3byte := w3.Marshal()
	hw1 := param.H(w1byte)
	w1w2 := append(w1byte, w2byte...)
	hw1w2 := param.H(w1w2)
	w2w3 := append(w2byte, w3byte...)
	hw2w3 := param.H(w2w3)
	temp2 := append(hw1.Bytes(), hw1w2.Bytes()...)
	w4 := param.H(append(temp2, hw2w3.Bytes()...))

	cp := &Cp{
		W1: w1,
		W2: w2,
		W3: w3,
		W4: w4,
	}
	return cp
}

func Dec(param *Param, cp *Cp, skj *big.Int) *bn128.GT {
	temp := bn128.Pair(cp.W1, cp.W3)
	temp.ScalarMult(temp, skj)
	temp.Neg(temp)
	m := new(bn128.GT).Add(cp.W2, temp)
	return m
}
