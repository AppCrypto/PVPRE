package gss

import (
	"crypto/rand"
	"errors"
	"math/big"

	bn128 "github.com/fentec-project/bn256"
	// bn128 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// 公共参数结构体
type PublicParameters struct {
	G     *bn128.G1  //群G的生成元
	P     *big.Int   //群的阶
	N     int        // 分享个数
	T     int        //阈值
	Alpah []*big.Int //随机值
}

// 生成公共参
func GsSetup(n, t int) (*PublicParameters, error) {
	//使用bn128曲线的生成元
	G := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	p := bn128.Order
	// 随机选择 n 个 α_i
	alpha := make([]*big.Int, n+1)
	for i := 0; i <= n; i++ {
		alpha[i], _ = rand.Int(rand.Reader, p)
	}

	gsspp := &PublicParameters{
		G:     G,
		P:     p,
		N:     n,
		T:     t,
		Alpah: alpha,
	}
	return gsspp, nil
}

func GsShare(gsspp *PublicParameters, secret *big.Int) ([]*bn128.G1, error) {
	// 随即生成多项式系数
	coefficients := make([]*big.Int, gsspp.T)
	coefficients[0] = new(big.Int).SetInt64(0) // 初始化为0
	for i := 1; i < gsspp.T; i++ {
		coefficients[i], _ = rand.Int(rand.Reader, gsspp.P)
	}

	// 计算系数，使 m(α_0) = 0
	for i := 1; i < gsspp.T; i++ {
		term := new(big.Int).Mul(coefficients[i], new(big.Int).Exp(gsspp.Alpah[0], big.NewInt(int64(i)), gsspp.P))
		term.Mod(term, gsspp.P)
		coefficients[0].Add(coefficients[0], term)
		coefficients[0].Mod(coefficients[0], gsspp.P)
	}

	// 确保 m(α_0) = 0，调整第一个系数
	coefficients[0].Neg(coefficients[0])
	coefficients[0].Mod(coefficients[0], gsspp.P)

	// result := evaluatePolynomial(coefficients, gsspp.Alpah[0], gsspp.P)
	// fmt.Print("m(\alpha_0) = ", result)

	// 计算每个share
	shares := make([]*bn128.G1, gsspp.N)
	S := new(bn128.G1).ScalarBaseMult(secret)
	for i := 0; i < gsspp.N; i++ {
		alpha := gsspp.Alpah[i+1]                                  //用i作为x的值
		mAlpha := evaluatePolynomial(coefficients, alpha, gsspp.P) //计算m(i)
		temp := new(bn128.G1).ScalarBaseMult(mAlpha)
		shares[i] = new(bn128.G1).Add(S, temp) //计算G上的元素
	}

	return shares, nil
}

// evaluatePolynomial 在给定的 x 处计算多项式的值
func evaluatePolynomial(coefficients []*big.Int, x, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
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

// 预计算拉格朗日系数
func PrecomputeLagrangeCoefficients(gsspp *PublicParameters, I []int) ([]*big.Int, error) {
	// 检查I是否包含足够的份额来恢复秘密
	if len(I) < gsspp.T {
		return nil, errors.New("not enough shares to recover the secret")
	}

	// 计算所有拉格朗日系数
	lambdas := make([]*big.Int, len(I))
	for i := 0; i < len(I); i++ {
		alpha_i := gsspp.Alpah[I[i]]
		lambda_i := big.NewInt(1)
		for j := 0; j < len(I); j++ {
			if i != j {
				alpha_j := gsspp.Alpah[I[j]]
				// λ_i = λ_i * (0 - α_j) / (α_i - α_j) mod p
				num := new(big.Int).Sub(gsspp.Alpah[0], alpha_j) // 拉格朗日系数分子部分
				den := new(big.Int).Sub(alpha_i, alpha_j)        // 拉格朗日分母部分
				den.ModInverse(den, gsspp.P)                     // 求逆

				lambda_i.Mul(lambda_i, num)
				lambda_i.Mul(lambda_i, den)
				lambda_i.Mod(lambda_i, gsspp.P)
			}
		}
		lambdas[i] = lambda_i
	}

	return lambdas, nil
}

// 接收预计算的拉格朗日系数 `lambdas`，索引集合 `I`，以及分享值 `shares`，返回恢复的秘密 `S`
func GsRecon(gsspp *PublicParameters, I []int, shares []*bn128.G1, lambdas []*big.Int) (*bn128.G1, error) {
	// // 检查`I`是否包含足够的份额来恢复秘密
	// if len(I) < gsspp.T {
	// 	return nil, errors.New("not enough shares to recover the secret")
	// }

	// 初始化恢复的秘密 `S`
	S := new(bn128.G1).ScalarBaseMult(big.NewInt(0))

	// 使用预计算的拉格朗日系数并累加每个分享
	for i := 0; i < gsspp.T; i++ {
		y_i := shares[I[i]-1]
		lambda_i := lambdas[i]
		// 计算 λ_i * A_i 并累加到恢复的秘密 `S`
		temp := new(bn128.G1).ScalarMult(y_i, lambda_i)
		S.Add(S, temp)
	}

	return S, nil
}

// 接收公共参数 `gsspp`，索引集合 `I`，以及分享值 `shares`，返回恢复的秘密 `S`
// func GsRecon(gsspp *PublicParameters, I []int, shares []*bn128.G1) (*bn128.G1, error) {
// 	// 检查`I`是否包含足够的份额来恢复秘密
// 	if len(I) < gsspp.T {
// 		return nil, errors.New("not enough shares to recover the secret")
// 	}

// 	//初始化恢复的秘密`S`
// 	S := new(bn128.G1).ScalarBaseMult(big.NewInt(0))

// 	// 计算拉格朗日系数并累加每个分享
// 	for i := 0; i < len(I); i++ {
// 		// 获取当前的alpha_i
// 		alpha_i := gsspp.Alpah[I[i]]
// 		y_i := shares[I[i]-1]
// 		// 计算当前分享的拉格朗日系数lambda_i
// 		lambda_i := big.NewInt(1)
// 		for j := 0; j < len(I); j++ {
// 			if i != j {
// 				// lambda_i *= (0-x_j) / (x_i - x_j) mod p
// 				alpha_j := gsspp.Alpah[I[j]]
// 				// λ_i = λ_i * (0 - x_j) / (x_i - x_j) mod p
// 				num := new(big.Int).Sub(gsspp.Alpah[0], alpha_j) //拉格朗日系数分子部分
// 				den := new(big.Int).Sub(alpha_i, alpha_j)        //拉格朗日分母部分
// 				den.ModInverse(den, gsspp.P)                     // 求逆

// 				lambda_i.Mul(lambda_i, num)
// 				lambda_i.Mul(lambda_i, den)
// 				lambda_i.Mod(lambda_i, gsspp.P)
// 			}
// 		}
// 		// 计算 λ_i * A_i 并累加到恢复的秘密 `S`
// 		temp := new(bn128.G1).ScalarMult(y_i, lambda_i)
// 		S.Add(S, temp)
// 	}
// 	return S, nil
// }
