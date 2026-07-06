#include "utils-basics.h"
#include "utils-eval.h"
#include "utils-matrices.h"
#include "minimum.h"

#include <iostream>
#include <vector>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cassert>

using namespace lbcrypto;

// 슬롯 0 값을 앞쪽 k개 슬롯으로 복제 (오른쪽 회전: -1,-2,-4,...)
static Ciphertext<DCRTPoly> ReplicateFirstK(const CryptoContext<DCRTPoly>& cc,
                                            const Ciphertext<DCRTPoly>& c0,
                                            size_t k) {
    auto c = c0;
    for (size_t step = 1; step < k; step <<= 1) {
        auto r = cc->EvalRotate(c, -static_cast<int>(step)); // →
        c = cc->EvalAdd(c, r);
    }
    return c;
}

int main() {
    // ====== Bob's 2D data ======
    std::vector<double> vB1 = {0.83, -0.26, 0.49, 0.97, 0.12, 0.57, -0.38, 0.74};
    std::vector<double> vB2 = {0.45, 0.88, -0.33, 0.12, 0.67, -0.21, 0.91, 0.05};
    const size_t n = vB1.size();
    assert(vB1.size() == vB2.size()); // 두 차원의 크기가 같아야 함

    // ====== Initial 2D centroids sampled in [-B,B] x [-B,B] ======
    const double B = 1.0;
    const size_t k = 4;               

    const usint compareDepth   = 10;
    const usint indicatorDepth = 10;

    std::mt19937_64 rng(42);
    std::uniform_real_distribution<double> unif(-B, B);
    std::vector<double> cB1(k), cB2(k);
    for (size_t j = 0; j < k; ++j) {
        cB1[j] = unif(rng);
        cB2[j] = unif(rng);
    }

    // ====== CKKS's parameters ======
    const usint integralPrecision   = 1;
    const usint decimalPrecision    = 42;
    const usint multiplicativeDepth = 6 + compareDepth + indicatorDepth;
    const usint numSlots            = std::max(n, k * k);
    const bool   enableBootstrap    = false;
    const usint  ringDim            = 0;
    const bool   verbose            = true;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Demo: distance Di = sqrt((x1_i - c1_j)^2 + (x2_i - c2_j)^2) (Bob part only)\n";
    std::cout << "x1^B: " << vB1 << "\n";
    std::cout << "x2^B: " << vB2 << "\n";
    std::cout << "c1^B: " << cB1 << "\n";
    std::cout << "c2^B: " << cB2 << "\n\n";

    // ======CKKS context ======
    CryptoContext<DCRTPoly> cc = generateCryptoContext(
        integralPrecision, decimalPrecision, multiplicativeDepth,
        numSlots, enableBootstrap, ringDim, verbose);

    //Define CKKS's rotation key 
    std::vector<int32_t> rotIdx = getRotationIndices(k);
    for (int i = 0; i < static_cast<int>(n); ++i) {
        rotIdx.push_back(i);
        rotIdx.push_back(-i);
    }
    //Define rotaion key for encoding(CKKS rotation key랑 중복이긴 하나, 일단 둘다 생성)
    for (int p = 0; (1u << p) < static_cast<int>(std::max<size_t>(2, k)); ++p)
        rotIdx.push_back(-(1 << p));
    //Remove duplicates
    std::sort(rotIdx.begin(), rotIdx.end());
    rotIdx.erase(std::unique(rotIdx.begin(), rotIdx.end()), rotIdx.end());

    KeyPair<DCRTPoly> kp = keyGeneration(cc, rotIdx, numSlots, enableBootstrap, verbose);

    // ======Encrypt Bob's 2-dimensional data set ======
    std::cout << "Encrypting vB1, vB2 ... " << std::flush;
    std::vector<double> vPacked1(numSlots, 0.0), vPacked2(numSlots, 0.0);
    for (size_t j = 0; j < n; ++j) {
        vPacked1[j] = vB1[j];
        vPacked2[j] = vB2[j];
    }
    auto XB1 = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(vPacked1));
    auto XB2 = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(vPacked2));
    std::cout << "OK\n\n";

    // ====== K-means 반복 시작 ======
    const int max_iterations = 10;
    std::vector<double> cB1_initial = cB1;  // 초기 centroids 저장
    std::vector<double> cB2_initial = cB2;
    std::vector<double> cB1_current = cB1;  // 현재 centroids
    std::vector<double> cB2_current = cB2;
    
    for (int iter = 0; iter < max_iterations; ++iter) {
        std::cout << "\n=== K-means Iteration " << (iter + 1) << " ===" << std::endl;
        std::cout << "Current centroids:" << std::endl;
        std::cout << "  cB1: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB1_current[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;
        std::cout << "  cB2: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB2_current[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;

        // ====== Plaintext Packing on the current 2D centroids ======
        std::vector<double> cPacked1(numSlots, 0.0), cPacked2(numSlots, 0.0);
        for (size_t j = 0; j < k; ++j) {
            cPacked1[j] = cB1_current[j];
            cPacked2[j] = cB2_current[j];
        }
        auto pC1 = cc->MakeCKKSPackedPlaintext(cPacked1);
        auto pC2 = cc->MakeCKKSPackedPlaintext(cPacked2);

        // ====== A_i, T, S1^B, S2^B 준비 ======
        std::vector<Ciphertext<DCRTPoly>> A(n); // one-hot argmin 벡터들

    // 앞쪽 k 슬롯만 남기는 마스크
    std::vector<double> maskK(numSlots, 0.0);
    for (size_t j = 0; j < k; ++j) maskK[j] = 1.0;
    auto pMaskK = cc->MakeCKKSPackedPlaintext(maskK);

    std::cout << "vPacked1 full: " << vPacked1 << std::endl;
    std::cout << "vPacked2 full: " << vPacked2 << std::endl;
    std::cout << "cPacked1 full: " << cPacked1 << std::endl;
    std::cout << "cPacked2 full: " << cPacked2 << std::endl;
    Ciphertext<DCRTPoly> T;      // 클러스터별 포인트 개수
    Ciphertext<DCRTPoly> SB1, SB2;     // 클러스터별 x1^B, x2^B 합
    bool T_init  = false;
    bool SB1_init = false, SB2_init = false;

    // ================== i번째 성분 추출 + k 복제 + 2D 거리 계산 ==================
    for (size_t i = 0; i < n; ++i) {
        // 1) δ_{j=i} 마스크(one-hot)로 x1_i^B, x2_i^B만 남김
        std::vector<double> mask(n, 0.0); mask[i] = 1.0;
        auto pMask  = cc->MakeCKKSPackedPlaintext(mask);
        auto masked1 = cc->EvalMult(XB1, pMask);
        auto masked2 = cc->EvalMult(XB2, pMask);

        // 2) i번째 값을 슬롯 0으로 이동 (왼쪽 회전이 기본이므로 +i)
        auto x0_1 = (i == 0) ? masked1 : cc->EvalRotate(masked1, static_cast<int>(i));
        auto x0_2 = (i == 0) ? masked2 : cc->EvalRotate(masked2, static_cast<int>(i));

        // 3) RepIC: 슬롯0 값을 앞쪽 k칸으로 복제 -> X1_i^B = (x1_i^B,...,x1_i^B), X2_i^B = (x2_i^B,...,x2_i^B)
        auto xi1Rep = ReplicateFirstK(cc, x0_1, k);
        auto xi2Rep = ReplicateFirstK(cc, x0_2, k);

        // 4) Bob 파트 2D 거리: (xi1Rep - c1^B)^2 + (xi2Rep - c2^B)^2
        auto diff1 = cc->EvalSub(xi1Rep, pC1);
        auto diff2 = cc->EvalSub(xi2Rep, pC2);
        auto Di1_B = cc->EvalMult(diff1, diff1);  // (x1_i^B - c1_j^B)^2
        auto Di2_B = cc->EvalMult(diff2, diff2);  // (x2_i^B - c2_j^B)^2
        auto Di_B = cc->EvalAdd(Di1_B, Di2_B);    // 2D 유클리드 거리의 제곱

        // [0,8] -> [0,1] 정규화 (2D이므로 최대 거리가 더 클 수 있음)
        auto Di_B_norm = cc->EvalMult(Di_B, 0.125);

        // 디버깅용 출력
        Plaintext dec;
        cc->Decrypt(kp.secretKey, Di_B, &dec);
        dec->SetLength(k);
        auto out = dec->GetRealPackedValue();
        std::cout << "i=" << i << "  (x1_i,x2_i)=(" << vB1[i] << "," << vB2[i] << ")  Di_B = [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << out[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]";

        // ====== minimum.cpp를 이용한 argmin -> one-hot A_i ======
        auto indicatorC = min(
            Di_B_norm,               // 0.25를 나눠서 [0,1] 범위로 정규화된 거리
            k,
            -1.0, 1.0,               // demo와 동일한 범위
            depth2degree(compareDepth),
            depth2degree(indicatorDepth)
        );

         //Extract k components from  indicatorC on encrypted status
        auto Ai_raw = cc->EvalMult(indicatorC, pMaskK);
        
        //----Decrypt Ai_raw and apply tie-breaking logic ----
        Plaintext indicatorP;
        cc->Decrypt(kp.secretKey, Ai_raw, &indicatorP);
        indicatorP->SetLength(k);
        auto indicator = indicatorP->GetRealPackedValue();
        std::cout << "indicator slots: " << indicator  << std::endl;
        
        // Tie-breaking: 최대값을 가진 인덱스들 중 첫 번째 선택(오류 해결한 부분이기도 함.)
        size_t minJ = 0;
        double best = indicator[0];
        for (size_t j = 1; j < k; ++j) {
            if (indicator[j] > best) {
                best = indicator[j];
                minJ = j;
            }
        }
        
        // One-hot 벡터 생성 (tie-breaking 적용)
        std::vector<double> oneHot(numSlots, 0.0);
        oneHot[minJ] = 1.0;
        auto pOneHot = cc->MakeCKKSPackedPlaintext(oneHot);
        auto Ai = cc->Encrypt(kp.publicKey, pOneHot);  // 새로운 one-hot 벡터로 암호화
        A[i] = Ai;
        
        std::cout << "final one-hot cluster = " << minJ << "\n";

        // ====== 클러스터 평균 계산을 위한 T, S1^B, S2^B 누적 ======
        // T += A_i
        if (!T_init) {
            T = Ai;
            T_init = true;
        } else {
            T = cc->EvalAdd(T, Ai);
        }

        // S1^B += A_i * X1_i^B
        auto contrib1B = cc->EvalMult(Ai, xi1Rep);
        if (!SB1_init) {
            SB1 = contrib1B;
            SB1_init = true;
        } else {
            SB1 = cc->EvalAdd(SB1, contrib1B);
        }

        // S2^B += A_i * X2_i^B
        auto contrib2B = cc->EvalMult(Ai, xi2Rep);
        if (!SB2_init) {
            SB2 = contrib2B;
            SB2_init = true;
        } else {
            SB2 = cc->EvalAdd(SB2, contrib2B);
        }
    }

    // ====== 클러스터 크기 T, 합 SB1, SB2 복호 및 평균 계산 ======
    Plaintext Tdec;
    cc->Decrypt(kp.secretKey, T, &Tdec);
    Tdec->SetLength(k);
    auto Tvals = Tdec->GetRealPackedValue();

    Plaintext SB1dec, SB2dec;
    cc->Decrypt(kp.secretKey, SB1, &SB1dec);
    cc->Decrypt(kp.secretKey, SB2, &SB2dec);
    SB1dec->SetLength(k);
    SB2dec->SetLength(k);
    auto SB1vals = SB1dec->GetRealPackedValue();
    auto SB2vals = SB2dec->GetRealPackedValue();

        std::cout << "\nIteration " << (iter + 1) << " - Cluster sizes (T): [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << Tvals[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]\n";

        std::vector<double> cB1_new(k, 0.0), cB2_new(k, 0.0);
        for (size_t j = 0; j < k; ++j) {
            if (Tvals[j] > 0.5) { // 0.5 이상이면 그 클러스터에 포인트가 있다고 간주
                cB1_new[j] = SB1vals[j] / Tvals[j];
                cB2_new[j] = SB2vals[j] / Tvals[j];
            } else {
                cB1_new[j] = cB1_current[j]; // 비어있는 클러스터는 이전 값 유지
                cB2_new[j] = cB2_current[j];
            }
        }

        std::cout << "Updated centroids:" << std::endl;
        std::cout << "  cB1: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB1_new[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;
        std::cout << "  cB2: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB2_new[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;

        // ====== 수렴 조건 확인 ======
        double total_change = 0.0;
        for (size_t j = 0; j < k; ++j) {
            total_change += std::abs(cB1_new[j] - cB1_current[j]);
            total_change += std::abs(cB2_new[j] - cB2_current[j]);
        }
        std::cout << "Total centroid change: " << total_change << std::endl;

        // 수렴 임계값
        const double convergence_threshold = 1e-3;
        if (total_change < convergence_threshold) {
            std::cout << "*** Converged after " << (iter + 1) << " iterations ***" << std::endl;
            break;
        }

        // 다음 iteration을 위해 centroids 업데이트
        cB1_current = cB1_new;
        cB2_current = cB2_new;
    } // K-means 반복 종료

    std::cout << "\n=== Final Results ===" << std::endl;
    std::cout << "Initial centroids:" << std::endl;
    std::cout << "  cB1: [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB1_initial[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;
    std::cout << "  cB2: [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB2_initial[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;
    
    std::cout << "↓" << std::endl;
    
    std::cout << "Final centroids:" << std::endl;
    std::cout << "  cB1: [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB1_current[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;
    std::cout << "  cB2: [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB2_current[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;

    std::cout << "\nDone.\n";
    return 0;
}