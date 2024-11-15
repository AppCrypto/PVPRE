package dhpvss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"pvpre/crypto/dleq"
	"pvpre/crypto/gss"

	bn128 "github.com/fentec-project/bn256"
	// bn128 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// H:
type HFunc func([]byte) ([]*big.Int, error)

type Dhpvsspar struct {
	PP *gss.PublicParameters
	Vi []*big.Int //原文中pp中的vi
	H  HFunc
}

type DLEQProof struct {
	C  *big.Int
	Z  *big.Int
	XG *bn128.G1
	XH *bn128.G1
	RG *bn128.G1
	RH *bn128.G1
}

type DLEQProofs struct {
	C  []*big.Int
	Z  []*big.Int
	XG []*bn128.G1
	XH []*bn128.G1
	RG []*bn128.G1
	RH []*bn128.G1
}

func Hfunc(input []byte, n, t int) ([]*big.Int, error) {
	if t == n || t == n-1 {

		return []*big.Int{big.NewInt(1)}, nil //errors.New("t is too big, t < n-1")
	}
	hash := sha256.Sum256(input)            // 使用 sha256 进行哈希
	coefficients := make([]*big.Int, n-t-1) // 生成 n-t-1 个系数

	// 计算每个系数分配的字节数
	coefLength := 32 / (n - t - 1) // 每个系数的字节长度
	if coefLength == 0 {
		coefLength = 1 // 当 n-t-1 较大时，每个系数至少分配 1 个字节
	}

	// 计算多余字节
	leftoverBytes := 32 - (coefLength * (n - t - 1))

	// 使用均匀分配的字节生成每个系数
	index := 0
	for i := 0; i < n-t-1; i++ {
		start := index
		end := index + coefLength

		// 如果 end 超出 hash 长度，调整 end
		if end > len(hash) {
			end = len(hash)
		}

		// 从哈希值中提取字节，生成系数
		coefficients[i] = new(big.Int).SetBytes(hash[start:end])

		// 更新索引
		index = end
	}

	// 如果有剩余字节，循环填充系数
	if leftoverBytes > 0 {
		// 这里只会有多余字节需要分配到系数上
		for i := 0; i < leftoverBytes; i++ {
			// 避免重复赋值整个 hash，确保正确填充
			coefficients[i%len(coefficients)] = new(big.Int).SetBytes(hash[i:])
		}
	}

	return coefficients, nil
}

// 计算VI
// 在这里为我们取alpha为从1到n
func ComputeVI(alpha []*big.Int, p *big.Int) []*big.Int {
	// 用于保存所有的v_i值
	vValue := make([]*big.Int, len(alpha)-1)

	// 计算v_i:
	for i := 0; i < len(alpha)-1; i++ {
		// 初始化v_i为1
		v_i := big.NewInt(1)

		// 计算 v_i 的逆的乘积
		for j := 0; j < len(alpha)-1; j++ {
			if i != j {
				// Compute (alpha[i] - alpha[j])^-1 mod p
				diff := new(big.Int).Sub(alpha[i+1], alpha[j+1])
				diff.Mod(diff, p)                           // Ensure the difference is mod p
				inverse := new(big.Int).ModInverse(diff, p) // Compute the modular inverse

				if inverse == nil {
					// Handle the case where inverse does not exist (e.g., division by zero)
					fmt.Println("Inverse does not exist.")
					return nil
				}
				// Multiply the result by the inverse
				v_i.Mul(v_i, inverse)
				v_i.Mod(v_i, p) // Take result mod p
			}
		}
		vValue[i] = v_i
	}
	return vValue
}

// 生成系统参数
func DHPVSSSetup(n, t, l int) (*Dhpvsspar, *big.Int, error) {
	// 使用 gss 包中的 GsSetup 生成公共参数
	pp, err := gss.GsSetup(n, t)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating GsSetup: %v", err)
	}

	v_i := ComputeVI(pp.Alpah, pp.P)

	H := func(input []byte) ([]*big.Int, error) {
		// 使用 H 函数进行哈希处理
		return Hfunc(input, pp.N, pp.T) // Hfunc 函数用于返回多项式系数
	}

	// 生成私密值 s
	s := new(big.Int)
	s, _ = rand.Int(rand.Reader, pp.P) // 随机生成私密值
	// S := new(bn128.G1).ScalarBaseMult(s)

	Par := &Dhpvsspar{
		PP: pp,
		Vi: v_i,
		// KDF: KDF,
		H: H,
	}
	return Par, s, nil
}

func DHPVSSShare(Par *Dhpvsspar, pkb *bn128.G1, pka *bn128.G1, ska *big.Int, PKs []*bn128.G1, s *big.Int) ([]*bn128.G1, *DLEQProof) {
	// var C []*bn128.G1
	// 初始化C切片大小为PKs的长度
	C := make([]*bn128.G1, Par.PP.N)
	// 初始化U和V
	U := new(bn128.G1)
	V := new(bn128.G1)

	shares, err := gss.GsShare(Par.PP, s)
	if err != nil {
		fmt.Printf("Error generating shares: %v", err)
	}
	if len(shares) != Par.PP.N {
		fmt.Printf("Expected %d shares, got %d", Par.PP.N, len(shares))
	}

	for i := 0; i < len(PKs); i++ {
		// 计算(pk_i * pkb)^{sk_a}
		temp := new(bn128.G1).Add(PKs[i], pkb)
		temp.ScalarMult(temp, ska)
		// 计算份额的密文
		C[i] = new(bn128.G1).Add(temp, shares[i])
	}
	// 将 pka, pkb, {pki, Ci} 转换为字节切片
	var input []byte

	input = append(input, pka.Marshal()...)
	input = append(input, pkb.Marshal()...)
	for i := 0; i < len(PKs); i++ {
		input = append(input, PKs[i].Marshal()...)
		input = append(input, C[i].Marshal()...)
	}

	// 生成m*
	// var mx []*big.Int
	mx, err := Par.H(input)
	if err != nil {
		fmt.Printf("Error reconstructing secret: %v", err)
	}
	for i := 0; i < len(mx); i++ {
		mx[i] = mx[i].Mod(mx[i], Par.PP.P)
	}

	// mi := evaluatePolynomial(mx, Par.PP.Alpah[1], Par.PP.P)
	// exp := new(big.Int).Mul(mi, Par.Vi[0])

	// start := time.Now()
	// for i := 0; i < Par.PP.N; i++ {
	// 	// m*(\alpha_i)
	// 	mi := evaluatePolynomial(mx, Par.PP.Alpah[i+1], Par.PP.P)
	// 	// m*(\alpha_i) * v_i
	// 	exp := new(big.Int).Mul(mi, Par.Vi[i])
	// 	fmt.Println("exp = ", exp)
	// 	_ = new(bn128.G1).ScalarMult(C[i], exp)
	// 	// V.Add(V, result1)
	// 	// temp := new(bn128.G1).Add(PKs[i], pkb)
	// 	// _ = temp.ScalarMult(temp, exp)
	// 	// U.Add(U, result2)
	// }
	// end := time.Now()

	// total := end.Sub(start)
	// fmt.Println("Tatol time cost :", total)

	// start := time.Now()

	// 求V和U
	for i := 0; i < Par.PP.N; i++ {
		// m*(\alpha_i)
		mi := evaluatePolynomial(mx, Par.PP.Alpah[i+1], Par.PP.P)
		// m*(\alpha_i) * v_i
		exp := new(big.Int).Mul(mi, Par.Vi[i])
		exp = exp.Mod(exp, Par.PP.P)
		result1 := new(bn128.G1).ScalarMult(C[i], exp)
		V.Add(V, result1)
		temp := new(bn128.G1).Add(PKs[i], pkb)
		result2 := temp.ScalarMult(temp, exp)
		U.Add(U, result2)
	}
	// end := time.Now()

	// 生成证明
	c, z, rG, rH, err := dleq.NewDLEQProof(Par.PP.G, U, pka, V, ska)
	if err != nil {
		fmt.Println("Failed to create DLEQ proof:", err)
	}
	// var pi_sh *DLEQProof
	pi_sh := &DLEQProof{C: c, Z: z, XG: pka, XH: V, RG: rG, RH: rH}
	return C, pi_sh
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

// 验证份额正确性
func DHPVSSVerify(Par *Dhpvsspar, pka *bn128.G1, pkb *bn128.G1, C []*bn128.G1, PKs []*bn128.G1, pi_sh *DLEQProof) bool {

	// 将 pka, pkb, {pki, Ci} 转换为字节切片
	var input []byte
	var U, V *bn128.G1
	// 初始化U和V
	U = new(bn128.G1)
	V = new(bn128.G1)

	input = append(input, pka.Marshal()...)
	input = append(input, pkb.Marshal()...)
	for i := 0; i < Par.PP.N; i++ {
		input = append(input, PKs[i].Marshal()...)
		input = append(input, C[i].Marshal()...)
	}
	// 生成m*
	// var mx []*big.Int
	mx, err := Par.H(input)
	if err != nil {
		fmt.Printf("Error reconstructing secret: %v", err)
	}
	for i := 0; i < len(mx); i++ {
		mx[i] = mx[i].Mod(mx[i], Par.PP.P)
	}
	// fmt.Println("len(mx)", len(mx))
	// 求V和U
	for i := 0; i < Par.PP.N; i++ {
		// m*(\alpha_i)
		mi := evaluatePolynomial(mx, Par.PP.Alpah[i+1], Par.PP.P)
		// m*(\alpha_i) * v_i
		exp := new(big.Int).Mul(mi, Par.Vi[i])
		exp = exp.Mod(exp, Par.PP.P)
		result1 := new(bn128.G1).ScalarMult(C[i], exp)
		V.Add(V, result1)
		temp := new(bn128.G1).Add(PKs[i], pkb)
		result2 := temp.ScalarMult(temp, exp)
		U.Add(U, result2)
	}
	err1 := dleq.Verify(pi_sh.C, pi_sh.Z, Par.PP.G, U, pi_sh.XG, pi_sh.XH, pi_sh.RG, pi_sh.RH)
	if err1 != nil {
		fmt.Println("Verification failed:", err) // 打印错误信息
		return false
	}
	return true
}

func DHPVSSPreRecon(Par *Dhpvsspar, pka *bn128.G1, PKs []*bn128.G1, SKs []*big.Int, C []*bn128.G1) ([]*bn128.G1, *DLEQProofs) {
	// C'
	var Cp, Xh []*bn128.G1
	// 初始化C切片大小为PKs的长度
	Cp = make([]*bn128.G1, len(C))
	Xh = make([]*bn128.G1, len(C))

	// var pi_re *DLEQProofs
	// 计算Cp = C/pka^{ski}
	for i := 0; i < len(C); i++ {
		temp := new(bn128.G1).ScalarMult(pka, SKs[i])
		temp.Neg(temp)
		Cp[i] = new(bn128.G1).Add(C[i], temp)
		// 生成DLEQ证明
		Xh[i] = new(bn128.G1).Neg(Cp[i])
		Xh[i].Add(C[i], Xh[i])
	}
	mul_G := make([]*bn128.G1, len(C))
	// copy(mul_G, []*bn128.G1{Par.PP.G})
	mul_H := make([]*bn128.G1, len(C))
	// copy(mul_H, []*bn128.G1{pka})
	for i := 0; i < len(C); i++ {
		mul_G[i] = Par.PP.G
		mul_H[i] = pka
	}

	mul_C, mul_Z, mul_XG, mul_XH, mul_RG, mul_RH, err := dleq.Mul_NewDLEQProof(mul_G, mul_H, PKs, Xh, SKs)
	if err != nil {
		fmt.Println("Verification failed:", err) // 打印错误信
	}
	pi_re := &DLEQProofs{C: mul_C, Z: mul_Z, XG: mul_XG, XH: mul_XH, RG: mul_RG, RH: mul_RH}
	return Cp, pi_re
}

func DHPVSSVerifyDec(Par *Dhpvsspar, pka *bn128.G1, PKs []*bn128.G1, C []*bn128.G1, Cp []*bn128.G1, pi_re *DLEQProofs) bool {
	// 验证生成的证明
	mul_G := make([]*bn128.G1, len(C))
	// copy(mul_G, []*bn128.G1{Par.PP.G})
	mul_H := make([]*bn128.G1, len(C))
	// copy(mul_H, []*bn128.G1{pka})
	// 初始化mul_G和mul_H
	for i := 0; i < len(C); i++ {
		mul_G[i] = Par.PP.G // 确保 Par.PP.G 已正确初始化
		mul_H[i] = pka      // 确保 pka 已正确初始化
	}
	var num int // 统计出错的个数
	num, err := dleq.Mul_Verify(pi_re.C, pi_re.Z, mul_G, mul_H, pi_re.XG, pi_re.XH, pi_re.RG, pi_re.RH)
	if err != nil {
		fmt.Printf("%v Proof's Verification failed: %v", num, err)
		return num <= Par.PP.N-Par.PP.T
	}
	// 输出结果
	// fmt.Println("All proofs verified successfully.")
	return true
}

func DHPVSSRecon(Par *Dhpvsspar, Cp []*bn128.G1, pka *bn128.G1, skb *big.Int, I []int, lambda []*big.Int) *bn128.G1 {
	// var shares []*bn128.G1
	shares := make([]*bn128.G1, Par.PP.T)
	temp := new(bn128.G1).ScalarMult(pka, skb)
	temp.Neg(temp)
	for i := 0; i < Par.PP.T; i++ {
		shares[i] = new(bn128.G1).Add(Cp[i], temp)
	}
	// var S bn128.G1
	S, err := gss.GsRecon(Par.PP, I, shares, lambda)
	if err != nil {
		fmt.Println(("Error reconstructing secret"))
	}
	return S
}
