package ukem

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	bn128 "github.com/fentec-project/bn256"
	"golang.org/x/crypto/hkdf"
)

type Hfunc2 func(P1, P2 *bn128.G1) *big.Int

type Hfunc3 func(P1, P2, P3 *bn128.G1) *big.Int

type Hfunc4 func(P1 *bn128.G1, scalar *big.Int, P2, P3, P4, P5 *bn128.G1) *big.Int

type Capsule struct {
	E *bn128.G1
	V *bn128.G1
	s *big.Int
}

type Params struct {
	G  *bn128.G1 //群G的生成元
	Q  *big.Int  //群的阶
	U  *bn128.G1 //群G的另一个生成元
	H2 Hfunc2
	H3 Hfunc3
	H4 Hfunc4
	N  int // 分享个数
	T  int //阈值,为了方便使用，在这里将N和T包含在公共参数中
}

type KFrag struct {
	Id  *big.Int
	Rk  *big.Int
	X_A *bn128.G1
	U1  *bn128.G1
	Z1  *big.Int
	Z2  *big.Int
}

type CFrag struct {
	E1 *bn128.G1
	V1 *bn128.G1
	Id *big.Int
	X  *bn128.G1
}

// type CKFrag struct {
// 	ID     *big.Int
// 	RK     *big.Int
// 	XComp  *bn128.G1
// 	XCompp *bn128.G1
// 	U1     *bn128.G1
// 	Z1     *big.Int
// 	Z2     *big.Int
// }

func H2(P1, P2 *bn128.G1) *big.Int {

	bytesP1 := append(P1.Marshal(), P2.Marshal()...) // Combine the byte representations of P1 and P2
	hash := sha256.Sum256(bytesP1)

	hashInt := new(big.Int).SetBytes(hash[:])

	// Use modulo q (field order of G2) to get an element in G2
	q := bn128.Order // q is the order of the field
	hashInt.Mod(hashInt, q)
	return hashInt
}

func H3(P1, P2, P3 *bn128.G1) *big.Int {
	// Serialize the points P1, P2, and P3
	bytesP1 := append(P1.Marshal(), P2.Marshal()...) // Combine the byte representations of P1 and P2
	bytesP1 = append(bytesP1, P3.Marshal()...)       // Add the byte representation of P3

	// Hash the combined input to get a fixed-size output
	hash := sha256.Sum256(bytesP1)

	// Convert the hash to a big integer
	hashInt := new(big.Int).SetBytes(hash[:])

	// Use modulo q (field order) to get an element in Z_q
	q := bn128.Order // q is the order of the group
	hashInt.Mod(hashInt, q)

	return hashInt
}

func H4(P1 *bn128.G1, scalar *big.Int, P2, P3, P4, P5 *bn128.G1) *big.Int {
	// Serialize the points P1, P2, P3, P4, P5
	bytesP1 := P1.Marshal()
	bytesScalar := scalar.Bytes()
	bytesP2 := P2.Marshal()
	bytesP3 := P3.Marshal()
	bytesP4 := P4.Marshal()
	bytesP5 := P5.Marshal()

	// Combine the byte representations of all inputs
	combinedBytes := append(bytesP1, bytesScalar...)
	combinedBytes = append(combinedBytes, bytesP2...)
	combinedBytes = append(combinedBytes, bytesP3...)
	combinedBytes = append(combinedBytes, bytesP4...)
	combinedBytes = append(combinedBytes, bytesP5...)

	// Hash the combined input to get a fixed-size output
	hash := sha256.Sum256(combinedBytes)

	// Convert the hash to a big integer
	hashInt := new(big.Int).SetBytes(hash[:])

	// Use modulo q (field order) to get an element in Z_q
	q := bn128.Order // q is the order of the group
	hashInt.Mod(hashInt, q)

	return hashInt
}

// H5 哈希函数，输入两个 big.Int，输出 big.Int
func H5(a, b *big.Int) *big.Int {
	// 将两个 big.Int 转换为字节数组
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	// 合并两个字节数组
	data := append(aBytes, bBytes...)

	// 对合并后的数据进行 SHA-256 哈希
	hash := sha256.Sum256(data)

	// 将哈希结果映射到 int 类型
	// 我们取哈希结果的前四个字节（32位），并将其转换为一个 int 类型的值
	// 注意：此处的转换方式仅为示例，具体取决于您需要的转换方式
	hashInt := new(big.Int).SetBytes(hash[:4]) // 取前四个字节，形成一个 big.Int
	return hashInt                             // 转换为 int 类型
}

func Setup(n, t int) *Params {

	G := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	Q := bn128.Order
	U := new(bn128.G1).ScalarBaseMult(big.NewInt(2))

	H2 := func(P1, P2 *bn128.G1) *big.Int {
		return H2(P1, P2)
	}

	H3 := func(P1, P2, P3 *bn128.G1) *big.Int {
		return H3(P1, P2, P3)
	}

	H4 := func(P1 *bn128.G1, scalar *big.Int, P2, P3, P4, P5 *bn128.G1) *big.Int {
		return H4(P1, scalar, P2, P3, P4, P5)
	}

	N := n
	T := t

	Params := &Params{
		G:  G,
		Q:  Q,
		U:  U,
		H2: H2,
		H3: H3,
		H4: H4,
		N:  N,
		T:  T,
	}
	return Params
}

func KeyGen(Params *Params) (*bn128.G1, *big.Int, *bn128.G1, *big.Int, []*bn128.G1, []*big.Int) {
	ska, _ := rand.Int(rand.Reader, Params.Q)
	skb, _ := rand.Int(rand.Reader, Params.Q)
	pka := new(bn128.G1).ScalarBaseMult(ska)
	pkb := new(bn128.G1).ScalarBaseMult(skb)
	PKs := make([]*bn128.G1, Params.N)
	SKs := make([]*big.Int, Params.N)
	for i := 0; i < Params.N; i++ {
		SKs[i], _ = rand.Int(rand.Reader, Params.Q)
		PKs[i] = new(bn128.G1).ScalarBaseMult(SKs[i])
	}
	return pka, ska, pkb, skb, PKs, SKs
}

func ReKeyGen(Params *Params, ska *big.Int, pka, pkb *bn128.G1) []*KFrag {
	kFrag := make([]*KFrag, Params.N)
	xa, _ := rand.Int(rand.Reader, Params.Q)
	X_A := new(bn128.G1).ScalarBaseMult(xa)
	temp := new(bn128.G1).ScalarMult(pkb, xa)
	d := Params.H3(X_A, pkb, temp)
	dn := d.ModInverse(d, Params.Q)
	// 生成随机多项式的系数
	coefficients := make([]*big.Int, Params.T) // 创建一个长度为 T 的切片来存储 t 个 big.Int 数值
	coefficients[0] = new(big.Int).Mul(ska, dn)
	coefficients[0].Mod(coefficients[0], Params.Q)
	for i := 1; i < Params.T; i++ { // 从第二个元素开始生成随机数
		coefficients[i], _ = rand.Int(rand.Reader, Params.Q) // 生成一个小于 P 的随机数
	}
	temp = new(bn128.G1).ScalarMult(pkb, ska)
	D := Params.H3(pka, pkb, temp)
	for i := 0; i < Params.N; i++ {
		y, _ := rand.Int(rand.Reader, Params.Q)
		id, _ := rand.Int(rand.Reader, Params.Q)
		sx := H5(id, D)
		Y := new(bn128.G1).ScalarBaseMult(y)
		rk := evaluatePolynomial(coefficients, sx, Params.Q)
		U1 := new(bn128.G1).ScalarMult(Params.U, rk)
		z1 := Params.H4(Y, id, pka, pkb, U1, X_A)
		temp := new(big.Int).Mul(ska, z1)
		z2 := new(big.Int).Sub(y, temp)
		kFrag[i] = &KFrag{
			Id:  id,
			Rk:  rk,
			X_A: X_A,
			U1:  U1,
			Z1:  z1,
			Z2:  z2,
		}
	}
	return kFrag
}

// evaluatePolynomial 在给定的 x 处计算多项式的值
func evaluatePolynomial(coefficients []*big.Int, x, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0]) // m(0) = secret
	xPower := new(big.Int).Set(x)

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		term.Mod(term, order)
		result.Add(result, term)
		result.Mod(result, order)
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, order)
	}

	return result
}

func kdf(keyElem *bn128.G1, keySize int) []byte {

	// 使用 Marshal 将 G1 点序列化为字节切片
	keyBytes := keyElem.Marshal()

	// 使用 hkdf 扩展密钥
	keyMaster := hkdf.New(sha256.New, keyBytes, nil, nil)

	// 派生密钥
	derivedKey := make([]byte, keySize)
	keyMaster.Read(derivedKey)

	return derivedKey
}

func Encapsualate(Params *Params, pka *bn128.G1) ([]byte, *Capsule) {
	r, _ := rand.Int(rand.Reader, Params.Q)
	u, _ := rand.Int(rand.Reader, Params.Q)
	E := new(bn128.G1).ScalarBaseMult(r)
	V := new(bn128.G1).ScalarBaseMult(u)
	temp := Params.H2(E, V)
	temp.Mul(r, temp)
	s := new(big.Int).Add(temp, u)
	Capsule := &Capsule{
		E: E,
		V: V,
		s: s,
	}
	exp := new(big.Int).Add(r, u)
	temp1 := new(bn128.G1).ScalarMult(pka, exp)
	K := kdf(temp1, 32)
	return K, Capsule
}

func CheckCapsule(Params *Params, Capsule *Capsule) bool {
	left := new(bn128.G1).ScalarBaseMult(Capsule.s)
	exp := Params.H2(Capsule.E, Capsule.V)
	right := new(bn128.G1).ScalarMult(Capsule.E, exp)
	right.Add(right, Capsule.V)
	if !(right.String() == left.String()) {
		fmt.Print("invalid proof")
		return false
	}
	return true
}

func Decapsulate(Params *Params, ska *big.Int, Capsule *Capsule) ([]byte, error) {
	CapsuleValidity := CheckCapsule(Params, Capsule)
	if !CapsuleValidity {
		return nil, errors.New("invalid Capsule")
	}
	temp := new(bn128.G1).Add(Capsule.E, Capsule.V)
	temp.ScalarMult(temp, ska)
	K := kdf(temp, 32)
	return K, nil
}

// 为简化代码，此处不再考虑不通过验证的情况
func ReEncapsulate(Params *Params, KFrag []*KFrag, Capsule *Capsule) []*CFrag {
	cFrag := make([]*CFrag, len(KFrag))
	for i := 0; i < len(KFrag); i++ {
		CapsuleValidity := CheckCapsule(Params, Capsule)
		if !CapsuleValidity {
			fmt.Printf("第 %v 个 代理检测Capsule是错误的", i+1)
		}
		E1 := new(bn128.G1).ScalarMult(Capsule.E, KFrag[i].Rk)
		V1 := new(bn128.G1).ScalarMult(Capsule.V, KFrag[i].Rk)
		cFrag[i] = &CFrag{
			E1: E1,
			V1: V1,
			Id: KFrag[i].Id,
			X:  KFrag[i].X_A,
		}
	}
	return cFrag
}

// 预计算拉格朗日系数
func PrecomputeLagrangeCoefficients(Params *Params, skb *big.Int, pkb, pka *bn128.G1, cFrag []*CFrag) ([]*big.Int, error) {
	sx := make([]*big.Int, Params.T)

	temp := new(bn128.G1).ScalarMult(pka, skb)
	D := Params.H3(pka, pkb, temp)
	for i := 0; i < Params.T; i++ {
		sx[i] = H5(cFrag[i].Id, D)
	}

	// 计算所有拉格朗日系数
	lambdas := make([]*big.Int, Params.T)
	for i := 0; i < Params.T; i++ {
		alpha_i := sx[i]
		lambda_i := big.NewInt(1)
		for j := 0; j < Params.T; j++ {
			if i != j {
				alpha_j := sx[j]
				// λ_i = λ_i * (0 - α_j) / (α_i - α_j) mod p
				num := new(big.Int).Neg(alpha_j)          // 拉格朗日系数分子部分
				den := new(big.Int).Sub(alpha_i, alpha_j) // 拉格朗日分母部分
				den.ModInverse(den, Params.Q)             // 求逆

				lambda_i.Mul(lambda_i, num)
				lambda_i.Mul(lambda_i, den)
				lambda_i.Mod(lambda_i, Params.Q)
			}
		}
		lambdas[i] = lambda_i
	}

	return lambdas, nil
}

func DecapsulateFrags(Params *Params, skb *big.Int, pkb, pka *bn128.G1, cFrag []*CFrag, lambda []*big.Int) []byte {
	// // 检查`I`是否包含足够的份额来恢复秘密
	// if len(I) < Params.T {
	// 	return nil, errors.New("not enough shares to recover the secret")
	// }

	// 初始化E‘，V’
	Ep := new(bn128.G1).ScalarBaseMult(big.NewInt(0))
	Vp := new(bn128.G1).ScalarBaseMult(big.NewInt(0))

	// sx := make([]*big.Int, Params.T)

	// temp := new(bn128.G1).ScalarMult(pka, skb)
	// D := Params.H3(pka, pkb, temp)
	// for i := 0; i < Params.T; i++ {
	// 	sx[i] = H5(cFrag[i].Id, D)
	// }
	// // 计算拉格朗日系数并累加每个分享
	// for i := 0; i < Params.T; i++ {
	// 	// 计算当前分享的拉格朗日系数lambda_i
	// 	lambda_i := big.NewInt(1)
	// 	for j := 0; j < Params.T; j++ {
	// 		if i != j {
	// 			// lambda_i *= (0-x_j) / (x_i - x_j) mod p
	// 			// λ_i = λ_i * (0 - x_j) / (x_i - x_j) mod p
	// 			num := new(big.Int).Neg(sx[j])        //拉格朗日系数分子部分
	// 			den := new(big.Int).Sub(sx[i], sx[j]) //拉格朗日分母部分
	// 			den.ModInverse(den, Params.Q)         // 求逆

	// 			lambda_i.Mul(lambda_i, num)
	// 			lambda_i.Mul(lambda_i, den)
	// 			lambda_i.Mod(lambda_i, Params.Q)
	// 		}
	// 	}
	// lambda :=
	for i := 0; i < Params.T; i++ {
		lambda_i := lambda[i]

		temp1 := new(bn128.G1).ScalarMult(cFrag[i].E1, lambda_i)
		Ep.Add(Ep, temp1)
		temp2 := new(bn128.G1).ScalarMult(cFrag[i].V1, lambda_i)
		Vp.Add(Vp, temp2)
	}

	XA := cFrag[0].X
	temp3 := new(bn128.G1).ScalarMult(XA, skb)
	d := Params.H3(XA, pkb, temp3)
	temp4 := new(bn128.G1).Add(Ep, Vp)
	temp5 := new(bn128.G1).ScalarMult(temp4, d)
	K := kdf(temp5, 32)
	return K
}
