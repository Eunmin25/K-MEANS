//2D K-means with encrypted centroid update (homomorphic division)

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
#include <cmath>

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
    const size_t dataCount = 16;   // 데이터 개수
    const double dataMin = -2.0;   // 데이터 최소값
    const double dataMax = 2.0;    // 데이터 최대값
    std::mt19937_64 dataRng(2026);
    std::uniform_real_distribution<double> dataUnif(dataMin, dataMax);
    std::vector<double> vB1(dataCount), vB2(dataCount);
    for (size_t i = 0; i < dataCount; ++i) {
        vB1[i] = dataUnif(dataRng);
        vB2[i] = dataUnif(dataRng);
    }
    const size_t n = vB1.size();
    assert(vB1.size() == vB2.size()); // 두 차원의 크기가 같아야 함

    // ====== Initial 2D centroids sampled in [-B,B] x [-B,B] ======
    const double B = 1.0;
    const size_t k = 3;               

    const usint compareDepth   = 8;
    const usint indicatorDepth = 8;
    const usint nzCompareDepth = 6;
    const usint divideDegree   = 31;

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
    const usint multiplicativeDepth = 10 + compareDepth + indicatorDepth;
    const usint numSlots            = std::max(n, k * k);
    const bool   enableBootstrap    = false;
    const usint  ringDim            = 0;
    const bool   verbose            = true;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Demo: 2D K-means with encrypted division\n";
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

    int max_iterations = 10;

    // ====== K-means 반복 시작 ======
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

            // ====== minimum.cpp를 이용한 argmin -> one-hot A_i ======
            auto indicatorC = min(
                Di_B_norm,               // 0.125를 곱해서 [0,1] 범위로 정규화된 거리
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
            
            // Tie-breaking: 최대값을 가진 인덱스들 중 첫 번째 선택
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

        // ====== Encrypted division: centroid = SB / T ======
        std::cout << "\n--- Encrypted Division: Compute Centroids ---" << std::endl;
        auto T_clean = T;
        auto SB1_clean = SB1;
        auto SB2_clean = SB2;

        // nz ~= 1(T>0.5), 0(T<=0.5). 빈 클러스터 보호용 마스크
        std::vector<double> halfVec(numSlots, 0.0), oneVec(numSlots, 0.0);
        for (size_t j = 0; j < k; ++j) {
            halfVec[j] = 0.5;
            oneVec[j] = 1.0;
        }
        auto pHalf = cc->MakeCKKSPackedPlaintext(halfVec);
        auto pOne = cc->MakeCKKSPackedPlaintext(oneVec);
        auto cHalf = cc->Encrypt(kp.publicKey, pHalf);//암호문 생성
        auto cOne = cc->Encrypt(kp.publicKey, pOne);
        auto nz = compareGt(T_clean, cHalf, -1.0, static_cast<double>(n + 1), depth2degree(nzCompareDepth));
        auto oneMinusNz = cc->EvalSub(cOne, nz);

        // EvalDivide는 x>=1 구간에서 1/x 근사. T_safe로 0 분모 방지
        auto T_safe = cc->EvalAdd(T_clean, oneMinusNz);
        auto invT = cc->EvalDivide(T_safe, 1.0, static_cast<double>(n + 1), divideDegree);
        auto c1_div = cc->EvalMult(SB1_clean, invT);
        auto c2_div = cc->EvalMult(SB2_clean, invT);

        // Empty cluster용 reseed 후보를 생성하고 암호문에서 블렌딩
        std::vector<double> reseed1(numSlots, 0.0), reseed2(numSlots, 0.0);
        for (size_t j = 0; j < k; ++j) {
            reseed1[j] = dataUnif(dataRng);
            reseed2[j] = dataUnif(dataRng);
        }
        auto pReseed1 = cc->MakeCKKSPackedPlaintext(reseed1);
        auto pReseed2 = cc->MakeCKKSPackedPlaintext(reseed2);
        auto cReseed1 = cc->Encrypt(kp.publicKey, pReseed1);
        auto cReseed2 = cc->Encrypt(kp.publicKey, pReseed2);

        // non-empty는 업데이트값, empty는 reseed 후보를 사용
        auto Centroid1_recovered = cc->EvalAdd(cc->EvalMult(nz, c1_div), cc->EvalMult(oneMinusNz, cReseed1));
        auto Centroid2_recovered = cc->EvalAdd(cc->EvalMult(nz, c2_div), cc->EvalMult(oneMinusNz, cReseed2));

        // 출력/검증을 위해 여기서만 복호화
        Plaintext Tdec_clean;
        cc->Decrypt(kp.secretKey, T_clean, &Tdec_clean);
        Tdec_clean->SetLength(k);
        auto Tvals_clean = Tdec_clean->GetRealPackedValue();

        std::cout << "Cluster sizes (T): [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << Tvals_clean[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;
        std::cout << "Reseed policy: empty clusters use encrypted reseed candidates" << std::endl;

        // Alice가 복호화하여 원본 centroid 확인
        Plaintext centroid1_recovered_dec, centroid2_recovered_dec;
        cc->Decrypt(kp.secretKey, Centroid1_recovered, &centroid1_recovered_dec);
        cc->Decrypt(kp.secretKey, Centroid2_recovered, &centroid2_recovered_dec);
        centroid1_recovered_dec->SetLength(k);
        centroid2_recovered_dec->SetLength(k);
        auto cB1_recovered = centroid1_recovered_dec->GetRealPackedValue();
        auto cB2_recovered = centroid2_recovered_dec->GetRealPackedValue();

        std::cout << "Recovered centroids (from encrypted division):" << std::endl;
        std::cout << "  cB1: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB1_recovered[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;
        std::cout << "  cB2: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB2_recovered[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;

        // ====== 검증: 원본 centroid 계산 (노이즈 없이 직접 계산) ======
        std::cout << "\n--- Verification: True Original Centroids ---" << std::endl;
        
        Plaintext SB1dec_original, SB2dec_original;
        cc->Decrypt(kp.secretKey, SB1, &SB1dec_original);
        cc->Decrypt(kp.secretKey, SB2, &SB2dec_original);
        SB1dec_original->SetLength(k);
        SB2dec_original->SetLength(k);
        auto SB1vals_original = SB1dec_original->GetRealPackedValue();
        auto SB2vals_original = SB2dec_original->GetRealPackedValue();
        
        std::vector<double> cB1_new_original(k, 0.0), cB2_new_original(k, 0.0);
        for (size_t j = 0; j < k; ++j) {
            if (Tvals_clean[j] > 0.5) {
                cB1_new_original[j] = SB1vals_original[j] / Tvals_clean[j];
                cB2_new_original[j] = SB2vals_original[j] / Tvals_clean[j];
            } else {
                // 암호문 reseed 정책을 검증 기준에도 반영
                cB1_new_original[j] = reseed1[j];
                cB2_new_original[j] = reseed2[j];
            }
        }

        std::cout << "True original centroids (SB/T):" << std::endl;
        std::cout << "  cB1: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB1_new_original[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;
        std::cout << "  cB2: [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << cB2_new_original[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]" << std::endl;

        // ====== 오차 분석 ======
        std::cout << "\n--- Error Analysis ---" << std::endl;
        double total_error1 = 0.0, total_error2 = 0.0;
        for (size_t j = 0; j < k; ++j) {
            double error1 = std::abs(cB1_recovered[j] - cB1_new_original[j]);
            double error2 = std::abs(cB2_recovered[j] - cB2_new_original[j]);
            std::cout << "Cluster " << j << ": cB1 error = " << std::fixed << std::setprecision(6) 
                      << error1 << ", cB2 error = " << error2 << std::endl;
            total_error1 += error1;
            total_error2 += error2;
        }
        std::cout << "Average recovery error: cB1 = " << total_error1 / k 
                  << ", cB2 = " << total_error2 / k << std::endl;
        std::cout << "Note: Small errors are due to CKKS approximation." << std::endl;

        // ====== 수렴 조건 확인 ======
        double total_change = 0.0;
        for (size_t j = 0; j < k; ++j) {
            total_change += std::abs(cB1_recovered[j] - cB1_current[j]);
            total_change += std::abs(cB2_recovered[j] - cB2_current[j]);
        }
        std::cout << "Total centroid change: " << total_change << std::endl;

        // 수렴 임계값
        const double convergence_threshold = 1e-3;
        if (total_change < convergence_threshold) {
            std::cout << "*** Converged after " << (iter + 1) << " iterations ***" << std::endl;
            
            // 최종 결과 저장
            cB1_current = cB1_recovered;
            cB2_current = cB2_recovered;
            break;
        }

        // 다음 iteration을 위해 centroids 업데이트
        cB1_current = cB1_recovered;
        cB2_current = cB2_recovered;
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
    
    std::cout << "Final centroids (encrypted division):" << std::endl;
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
