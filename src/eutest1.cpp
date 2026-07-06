//Code with Differential Privacy

#include "utils-basics.h"
#include "utils-eval.h"
#include "utils-matrices.h"
#include "minimum.h"

#include <iostream>
#include <vector>
#include <iomanip>
#include <random>
#include <algorithm>
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
    // ======Bob's data ======
    std::vector<double> vB = {0.83, -0.26, 0.49, 0.97, 0.12, 0.57, -0.38, 0.74};
    const size_t n = vB.size();

    // ====== Initial centroids sampled in [-B,B] ======
    const double B = 1.0;
    const size_t k = 4;               

    const usint compareDepth   = 10;
    const usint indicatorDepth = 10;

    std::mt19937_64 rng(42);
    std::uniform_real_distribution<double> unif(-B, B);
    std::vector<double> cB(k);
    for (size_t j = 0; j < k; ++j) cB[j] = unif(rng);
    std::sort(cB.begin(), cB.end());  // 보기 좋게 정렬

    // ====== CKKS's parameters ======
    const usint integralPrecision   = 1;
    const usint decimalPrecision    = 42;
    const usint multiplicativeDepth = 6 + compareDepth + indicatorDepth;
    const usint numSlots            = std::max(n, k * k);
    const bool   enableBootstrap    = false;
    const usint  ringDim            = 0;
    const bool   verbose            = true;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Demo: distance Di = (x_i^B - c_j^B)^2 (Bob part only)\n";
    std::cout << "x^B: " << vB << "\n";
    std::cout << "c^B: " << cB << "\n\n";

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
    //Define rotaion key for encoding
    for (int p = 0; (1u << p) < static_cast<int>(std::max<size_t>(2, k)); ++p)
        rotIdx.push_back(-(1 << p));
    //Remove duplicates
    std::sort(rotIdx.begin(), rotIdx.end());
    rotIdx.erase(std::unique(rotIdx.begin(), rotIdx.end()), rotIdx.end());

    KeyPair<DCRTPoly> kp = keyGeneration(cc, rotIdx, numSlots, enableBootstrap, verbose);

    // ======Encrypt Bob's data ======
    std::cout << "Encrypting vB ... " << std::flush;
    std::vector<double> vPacked(numSlots, 0.0);
    for (size_t j = 0; j < n; ++j) vPacked[j] = vB[j];
    auto XB = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(vPacked));
    std::cout << "OK\n\n";

    // ====== Plaintext Packing on the initial centroids: [c1^B,...,ck^B, 0,...] ======
    std::vector<double> cPacked(numSlots, 0.0);
    for (size_t j = 0; j < k; ++j) cPacked[j] = cB[j];
    auto pC = cc->MakeCKKSPackedPlaintext(cPacked);

    // ====== A_i, T, S^B 준비 ======
    std::vector<Ciphertext<DCRTPoly>> A(n); // one-hot argmin 벡터들

    // 앞쪽 k 슬롯만 남기는 마스크
    std::vector<double> maskK(numSlots, 0.0);
    for (size_t j = 0; j < k; ++j) maskK[j] = 1.0;
    auto pMaskK = cc->MakeCKKSPackedPlaintext(maskK);

    std::cout << "vPacked full: " << vPacked << std::endl;
    std::cout << "cPacked full: " << cPacked << std::endl;
    Ciphertext<DCRTPoly> T;      // 클러스터별 포인트 개수
    Ciphertext<DCRTPoly> SB;     // 클러스터별 x^B 합
    bool T_init  = false;
    bool SB_init = false;

    // ================== i번째 성분 추출 + k 복제 + 거리 계산 ==================
    for (size_t i = 0; i < n; ++i) {
        // 1) δ_{j=i} 마스크(one-hot)로 x_i^B만 남김
        std::vector<double> mask(n, 0.0); mask[i] = 1.0;
        auto pMask  = cc->MakeCKKSPackedPlaintext(mask);
        auto masked = cc->EvalMult(XB, pMask);

        // 2) i번째 값을 슬롯 0으로 이동 (왼쪽 회전이 기본이므로 +i)
        auto x0 = (i == 0) ? masked : cc->EvalRotate(masked, static_cast<int>(i));

        // 3) RepIC: 슬롯0 값을 앞쪽 k칸으로 복제 -> X_i^B = (x_i^B,...,x_i^B)
        auto xiRep = ReplicateFirstK(cc, x0, k);

        // 4) Bob 파트 거리: (xiRep - c^B)^2
        auto diff = cc->EvalSub(xiRep, pC);
        auto Di_B = cc->EvalMult(diff, diff);  // (x_i^B - c_j^B)^2

        // [0,4] -> [0,1] 정규화
        auto Di_B_norm = cc->EvalMult(Di_B, 0.25);

        // 디버깅용 출력
        Plaintext dec;
        cc->Decrypt(kp.secretKey, Di_B, &dec);
        dec->SetLength(k);
        auto out = dec->GetRealPackedValue();
        std::cout << "i=" << i << "  x_i^B=" << vB[i] << "  Di_B = [ ";
        for (size_t j = 0; j < k; ++j)
            std::cout << out[j] << (j + 1 < k ? ", " : " ");
        std::cout << "]";

        // ====== minimum.cpp를 이용한 argmin -> one-hot A_i ======
        auto indicatorC = min(
            Di_B_norm,               // [0,1] 범위로 정규화된 거리
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
        
        std::cout << "final one-hot cluster = " << minJ << "\n";

        // ====== 클러스터 평균 계산을 위한 T, S^B 누적 ======
        // T += A_i
        if (!T_init) {
            T = Ai;
            T_init = true;
        } else {
            T = cc->EvalAdd(T, Ai);
        }

        // S^B += A_i * X_i^B
        auto contribB = cc->EvalMult(Ai, xiRep);
        if (!SB_init) {
            SB = contribB;
            SB_init = true;
        } else {
            SB = cc->EvalAdd(SB, contribB);
        }
    }

    // ====== Differential Privacy 파라미터 설정 ======
    std::cout << "\n=== Differential Privacy Parameters ===" << std::endl;
    
    // 전체 프라이버시 예산 (예시)
    double eps_total   = 1.0;   // ε
    double delta_total = 1e-5;  // δ

    int r = 1;  // 지금 코드는 한 번만 돌리니까 라운드 수 r=1이라고 가정
    double eps_round   = eps_total / r;    // ε'
    double delta_round = delta_total / r;  // δ'

    // 민감도 (정규화된 범위에 맞춤)
    double s_S = 2.0 * B * 0.25;  // 정규화에 맞춰 조정

    // 노이즈 표준편차 (SB에만 필요)
    double sigma_S = std::sqrt(2 * std::log(1.25 / delta_round)) * s_S / eps_round;

    // 가우시안 노이즈 생성기
    std::mt19937_64 rng_noise(12345); // DP용 별도 seed
    std::normal_distribution<double> gauss_noise(0.0, sigma_S);

    std::cout << "Privacy budget: eps = " << eps_round << ", delta = " << delta_round << std::endl;
    std::cout << "Sensitivity (normalized): s_S = " << s_S << std::endl;
    std::cout << "Noise std: sigma_S = " << sigma_S << std::endl;

    // ====== Alice: T는 그대로, SB에만 T*noise 추가 ======
    std::cout << "\n=== Alice: Adding DP Noise (T * noise to SB only) ===" << std::endl;
    
    // 먼저 T 값을 복호화 (Alice가 알아야 T*noise를 계산 가능)
    Plaintext Tdec_for_noise;
    cc->Decrypt(kp.secretKey, T, &Tdec_for_noise);
    Tdec_for_noise->SetLength(k);
    auto Tvals_original = Tdec_for_noise->GetRealPackedValue();
    
    // 노이즈 생성 (centroid에 더해질 값)
    std::vector<double> noise_centroid(numSlots, 0.0);
    for (size_t j = 0; j < k; ++j) {
        noise_centroid[j] = gauss_noise(rng_noise);
    }
    
    // SB에 T * noise 추가
    std::vector<double> noise_SB(numSlots, 0.0);
    for (size_t j = 0; j < k; ++j) {
        noise_SB[j] = Tvals_original[j] * noise_centroid[j];
    }
    
    auto pNoise_SB = cc->MakeCKKSPackedPlaintext(noise_SB);
    auto SB_noisy = cc->EvalAdd(SB, pNoise_SB);
    auto T_clean = T;  // T는 노이즈 없이 그대로

    std::cout << "Generated centroid noise: [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << std::fixed << std::setprecision(4) << noise_centroid[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;
    std::cout << "Applied SB noise (T * noise): [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << std::fixed << std::setprecision(4) << noise_SB[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;

    // ====== Bob: T_clean과 SB_noisy를 받아서 복호화 및 나눗셈 ======
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "\n=== Bob: Decrypt and Compute Centroids ===" << std::endl;
    
    Plaintext Tdec_clean;
    cc->Decrypt(kp.secretKey, T_clean, &Tdec_clean);
    Tdec_clean->SetLength(k);
    auto Tvals_clean = Tdec_clean->GetRealPackedValue();

    Plaintext SBdec_noisy;
    cc->Decrypt(kp.secretKey, SB_noisy, &SBdec_noisy);
    SBdec_noisy->SetLength(k);
    auto SBvals_noisy = SBdec_noisy->GetRealPackedValue();

    std::cout << "Cluster sizes (T - no noise): [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << Tvals_clean[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;

    // Bob이 centroid 계산: (SB + T*noise) / T = SB/T + noise
    std::vector<double> cB_noisy_computed(numSlots, 0.0);
    for (size_t j = 0; j < k; ++j) {
        if (Tvals_clean[j] > 0.5) {
            cB_noisy_computed[j] = SBvals_noisy[j] / Tvals_clean[j];
        } else {
            cB_noisy_computed[j] = cB[j]; // 기존 centroid 유지
        }
    }

    std::cout << "Bob's computed centroids (with noise): [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB_noisy_computed[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;

    // Bob이 결과를 다시 암호화해서 Alice에게 전송
    auto pCentroid_noisy = cc->MakeCKKSPackedPlaintext(cB_noisy_computed);
    auto Centroid_noisy_encrypted = cc->Encrypt(kp.publicKey, pCentroid_noisy);

    // ====== Alice: 노이즈 제거하여 원본 centroid 복원 ======
    std::cout << "\n=== Alice: Remove Noise to Recover Original Centroids ===" << std::endl;
    
    // Alice는 자신이 추가한 noise_centroid를 알고 있으므로 이를 빼면 원본 복원
    auto pNoise_centroid = cc->MakeCKKSPackedPlaintext(noise_centroid);
    auto Centroid_recovered = cc->EvalSub(Centroid_noisy_encrypted, pNoise_centroid);

    // Alice가 복호화하여 원본 centroid 확인
    Plaintext centroid_recovered_dec;
    cc->Decrypt(kp.secretKey, Centroid_recovered, &centroid_recovered_dec);
    centroid_recovered_dec->SetLength(k);
    auto cB_recovered = centroid_recovered_dec->GetRealPackedValue();

    std::cout << "Alice's recovered centroids (noise removed): [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB_recovered[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;

    // ====== 검증: 원본 centroid 계산 ======
    std::cout << "\n=== Verification ===" << std::endl;
    
    Plaintext SBdec_original;
    cc->Decrypt(kp.secretKey, SB, &SBdec_original);
    SBdec_original->SetLength(k);
    auto SBvals_original = SBdec_original->GetRealPackedValue();
    
    std::vector<double> cB_new_original(k, 0.0);
    for (size_t j = 0; j < k; ++j) {
        if (Tvals_clean[j] > 0.5) {
            cB_new_original[j] = SBvals_original[j] / Tvals_clean[j];
        } else {
            cB_new_original[j] = cB[j];
        }
    }

    std::cout << "True original centroids (SB/T): [ ";
    for (size_t j = 0; j < k; ++j)
        std::cout << cB_new_original[j] << (j + 1 < k ? ", " : " ");
    std::cout << "]" << std::endl;

    // ====== 오차 분석 ======
    std::cout << "\n=== Error Analysis ===" << std::endl;
    double total_error = 0.0;
    for (size_t j = 0; j < k; ++j) {
        double error = std::abs(cB_recovered[j] - cB_new_original[j]);
        std::cout << "Cluster " << j << ": recovery error = " << std::fixed << std::setprecision(6) 
                  << error << std::endl;
        total_error += error;
    }
    std::cout << "Average recovery error: " << total_error / k << std::endl;
    std::cout << "Note: Small errors are due to CKKS approximation, not DP noise!" << std::endl;

    std::cout << "\nDone.\n";
    return 0;
}