# WIP-6 VCT 테스트 보고서

## 환경

- 체인: Daejeon 테스트넷 (chainID 10399, vctBlock=100)
- 바이너리: `worldland-compat.exe` (호환성 테스트용 빌드)
- 플랫폼: Windows 11

---

## 1. 단위 테스트

### 1-1. VRF 암호 레이어 (`crypto/secp256k1/`)

`go test ./crypto/secp256k1/ -run TestVRF -v`

| 테스트 | 검증 내용 | 결과 |
|--------|----------|------|
| `TestVRFProveAndVerify` | VRFProve → VRFVerify 라운드트립, 출력 일치 | PASS |
| `TestVRFDeterministic` | 같은 (키, 메시지) → 항상 같은 출력 | PASS |
| `TestVRFDifferentMessages` | 다른 메시지 → 다른 출력 | PASS |
| `TestVRFDifferentKeys` | 다른 키 → 다른 출력 | PASS |
| `TestVRFWrongKeyVerify` | 잘못된 pubkey로 검증 시 실패 | PASS |
| `TestVRFProofToHash` | ProofToHash 출력 = VRFProve 출력 | PASS |
| `TestVRFWrongMessageVerify` | proof_A를 msg_B로 검증 시 실패 (재사용 공격 방지) | PASS |
| `TestVRFTamperedProofRejected` | 81바이트 proof 중 임의 1바이트 변조 → **81/81 거부** | PASS |

> `TestVRFTamperedProofRejected` 결과: proof의 모든 바이트 위치를 XOR 변조해도
> VRFVerify가 거부함. libsecp256k1 VRF 구현이 gamma point, c scalar, s scalar
> 전체를 검증하고 있음을 확인.

---

### 1-2. WIP-6 합의 레이어 (`consensus/vct/`)

`go test ./consensus/vct/ -v`

| 테스트 | 검증 내용 | 결과 |
|--------|----------|------|
| `TestVCTVRFProveVerify` | vct 패키지 VRF 라운드트립 | PASS |
| `TestVCTVRFDeriveKeys` | 결정론적 키 파생 (같은 입력 → 같은 키) | PASS |
| `TestVCTCheckSortition` | 정렬 임계값 판정 (패닉 없음, 결과 반환) | PASS |
| `TestWIP6MessageFormats` | VRF 메시지(79B), 채굴 서명 메시지, PoW 씨드, 레거시 씨드 형식 검증 | PASS |
| `TestLegacySealHashMatchesECCPoW` | `legacySealHash()` 출력 == `eccpow.SealHash()` 출력 | PASS |
| `TestWIP6ProgressiveTimeoutSortition` | SortitionBase 이하 즉시 통과, TimeoutEnd 시 전체 통과 | PASS |
| `TestWIP6MinEligibleBalanceAt` | S₀ 포크 전/후 잔액 임계값 전환 | PASS |
| `TestVCTVRFFullPipeline` | **전체 VRF 파이프라인 통합 테스트** (아래 상세) | PASS |

#### `TestVCTVRFFullPipeline` 상세

VRF 전체 경로를 단일 테스트로 검증:

```
SetVRFKey(seckey)
  → EnsureVRFKeys(coinbase)          // 키 등록 확인
  → IsEligibleForBlock()             // VRFProve 실행, 81B proof 생성
  → header.VRFProof = proof
  → header.VRFPublicKey = pubkey     // 33B 압축 공개키 임베드
  → header.Coinbase = PubkeyToAddress(prv)
  → verifyVRFProof()                 // PubkeyToAddress(VRFPublicKey)==Coinbase ✓
                                     // VRFVerify(pubkey, proof, msg) ✓
                                     // SortitionEligible(output, Δt≥TimeoutEnd) ✓
  → computeMiningSigMsgVCT(sealHash, nonce)
  → crypto.Sign(msg, prv) → σ_ν
  → verifyMiningSig()                // ECRecover(σ_ν)==Coinbase ✓
```

---

## 2. 2-노드 호환성 테스트 (라이브)

### 목적

기존 eccpow 노드(구 WorldLand 클라이언트)와 VCT 엔진 노드가  
하드포크(블록 100) 이전 구간에서 블록을 공유할 수 있는지 검증.

### 구성

| 노드 | 엔진 | 역할 | 포트 |
|------|------|------|------|
| eccpow | 기존 ECCPoW | 블록 1-99 채굴 | 30402 / RPC 9602 |
| vct | VCT (WIP-6) | 동기화 수신 | 30401 / RPC 9601 |
| eccpow-full | 기존 ECCPoW (full sync) | 상태 루트 검증 | 별도 |

두 노드 모두 동일한 제네시스 해시(`a37bd6..5f32ef`)로 초기화.  
eccpow-full은 `--syncmode full`로 모든 블록을 재실행하여 상태 루트를 검증.

### 테스트 케이스 및 결과

#### TC-1: eccpow → VCT 동기화 (하드포크 이전)

eccpow 노드가 블록 1-99를 채굴하고, VCT 노드가 P2P로 수신.

```
결과: Imported new chain segment blocks=97, number=99
```

**VCT 엔진이 eccpow-mined 블록을 검증 에러 없이 수락. ✅**

핵심 검증 포인트:
- `legacySealHash()` == eccpow의 SealHash — 동일한 봉인 해시 사용 확인
- `computeLegacyPowSeed()` — 기존 방식(prefix 없는 `sealHash||nonce`) 그대로 사용
- `accumulateRewardsLegacy()` — 4 WL 보상, treasury 없음 (상태 루트 일치)
- `verifyMiningSig` skip — 하드포크 이전 블록은 VRFSignature 검증 생략

#### TC-2: VCT → eccpow 헤더 검증

VCT 노드가 채굴한 블록 1-99를 기존 eccpow 노드가 수신.

```
결과: Imported new chain segment — 에러 없음
```

**기존 eccpow 노드가 VCT-엔진이 만든 pre-VCT 블록을 수락. ✅**

#### TC-3: 상태 루트 일치 검증 (eccpow full sync)

eccpow-full 노드가 `--syncmode full`로 블록 1-99를 재실행.

```
결과: Imported new chain segment blocks=97, number=97
       Imported new chain segment blocks=2,  number=99
```

**전체 재실행 후 상태 루트 일치. 블록 보상 로직이 동일함을 확인. ✅**

> 초기 실패 원인: VCT 엔진의 `accumulateRewards()`가 20 WL + treasury 분리를
> 하드포크 이전에도 적용. eccpow(4 WL, treasury 없음)와 상태 루트 불일치 발생.
> `accumulateRewardsLegacy()` 추가 후 해결.

#### TC-4: 하드포크 경계 동작 확인

VCT 노드가 블록 100 채굴 시도 (계정 잠금 해제 없음).

```
결과: Block sealing failed: VRF key error:
      unlock the account with --unlock before mining
```

**하드포크 이후 VRF 키 없이 채굴 불가. ✅**

---

## 3. 회귀 방지 테스트 목록

| 테스트 | 보호하는 불변성 |
|--------|----------------|
| `TestLegacySealHashMatchesECCPoW` | `legacySealHash()` ≡ `eccpow.SealHash()` |
| `TestWIP6MessageFormats` | 메시지 길이·레이아웃 변경 시 감지 |
| `TestVRFTamperedProofRejected` | VRFVerify가 변조된 proof를 거부함 |
| `TestVRFWrongMessageVerify` | VRF proof가 메시지에 바인딩됨 (재사용 불가) |
| `TestVCTVRFFullPipeline` | 전체 파이프라인 어느 단계가 깨져도 감지 |

---

## 4. 미검증 항목 (향후 과제)

| 항목 | 설명 |
|------|------|
| 라이브 VCT 블록 생성 | `--unlock` 후 블록 100 이상 실제 VRF 채굴 및 동기화 |
| S₀ 잔액 게이트 라이브 테스트 | 잔액 부족 계정으로 블록 100 이상 제안 시 거부 확인 |
| 동기화 재시작 안정성 | 노드 재시작 후 VRF proof 포함 블록 재검증 |
| snap sync + VCT | snap sync로 VCT 블록 헤더 + 상태 다운로드 검증 |
