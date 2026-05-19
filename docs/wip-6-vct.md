# WIP-6 VCT (Verifiable Coin Toss) 합의 프로토콜

## 개요

WIP-6는 WorldLand의 Daejeon 테스트넷(chainID 10399)에 도입된 합의 업그레이드로,  
기존 ECCPoW(LDPC) 위에 secp256k1 ECVRF 기반 제안자 정렬(sortition)을 추가한다.

- 엔진 패키지: `consensus/vct/`
- 하드포크 블록: `vctBlock` (genesis 설정값, Daejeon: 100)
- 블록 0 ~ vctBlock-1: Seoul ECCPoW (레거시 호환 모드)
- 블록 vctBlock 이상: VCT 합의 (VRF 정렬 + ECCPoW)

---

## 아키텍처

```
블록 제안 흐름
─────────────────────────────────────────────────────
Seal()
  ├─ IsVCT? No  → legacySealHash() + ECCPoW (legacyPowSeed)
  └─ IsVCT? Yes
       ├─ EnsureVRFKeys(coinbase)          계정 잠금 해제 확인
       ├─ IsEligibleForBlock()             VRF 증명 생성
       │    └─ VRFProve(seckey, pubkey, VCT_VRF||chainId||parentHash||h)
       ├─ SortitionEligible(output, Δt)    정렬 통과 확인
       ├─ header.VRFProof   ← proof 임베드
       │   header.VRFPublicKey ← 압축 공개키 임베드
       └─ mine_seoul() 루프
             per-nonce: Sign(VCT_MINE||sealHash||nonce) → VRFSignature
             powSeed = Keccak256(VCT_ECCPOW||sealHash||nonce||σ_ν)

블록 검증 흐름
─────────────────────────────────────────────────────
verifyHeader()
  ├─ IsVCT? No  → legacySealHash() 으로 verifySeal()
  └─ IsVCT? Yes
       ├─ verifySeal()       VCT sealHash + powSeedVCT
       ├─ verifyVRFProof()   proof 유효성 + coinbase 일치 + 정렬 임계값
       └─ verifyMiningSig()  ECRecover(σ_ν) == coinbase
```

---

## 핵심 데이터 구조

### 블록 헤더 추가 필드 (`core/types/block.go`)

| 필드 | 타입 | 설명 |
|------|------|------|
| `VRFProof` | `[]byte` (81B) | secp256k1 VRF 증명 |
| `VRFPublicKey` | `[]byte` (33B) | 압축 secp256k1 공개키 |
| `VRFSignature` | `[]byte` (65B) | 논스별 채굴 서명 σ_ν |

VCT 블록에서만 채워지며, 레거시 블록에서는 비어 있다.

### 메시지 도메인 분리

| 메시지 | 형식 | 용도 |
|--------|------|------|
| VRF 입력 | `VCT_VRF \|\| chainId(32B) \|\| parentHash(32B) \|\| h(8B BE)` | VRF 정렬 증명 |
| PoW 씨드 | `Keccak256(VCT_ECCPOW \|\| sealHash(32B) \|\| nonce(8B LE) \|\| σ_ν(65B))` | LDPC 해시 벡터 생성 |
| 채굴 서명 | `Keccak256(VCT_MINE \|\| sealHash(32B) \|\| nonce(8B LE))` | 논스 바인딩 서명 |
| SealHash | `Keccak256(VCT_SEAL \|\| chainId(32B) \|\| RLP(헤더 필드))` | VCT 전용 봉인 해시 |
| 레거시 SealHash | `Keccak256(RLP(헤더 필드))` | eccpow와 동일 (하드포크 전) |

---

## 레거시(하드포크 전) 호환성

하드포크 이전 블록(0 ~ vctBlock-1)은 기존 eccpow 엔진과 완전히 호환되어야 한다.

**핵심 차이점과 해결 방법:**

| 항목 | 기존 eccpow | VCT 엔진 (레거시 모드) |
|------|-------------|----------------------|
| SealHash | prefix 없음 | `legacySealHash()` — prefix 없음으로 동일하게 구현 |
| PoW 씨드 | `sealHash \|\| nonce` (raw) | `computeLegacyPowSeed()` — 동일 |
| 블록 보상 | 4 WL, treasury 없음 | `accumulateRewardsLegacy()` — 동일 |
| VRF 필드 | 없음 | 비워둠 (검증 시 스킵) |

### `legacySealHash()` (`consensus/vct/consensus.go`)

eccpow.SealHash()와 바이트 단위로 동일. `TestLegacySealHashMatchesECCPoW`로 회귀 테스트 보호됨.

---

## 진보적 타임아웃 정렬 (Progressive Timeout Sortition)

즉시 정렬 통과에 실패한 채굴자도 시간이 지남에 따라 기회를 얻는다.

| 상수 | 값 | 설명 |
|------|-----|------|
| `SortitionBase` | `0xA0` (160/256) | 즉시 통과 임계값 (≈62.5%) |
| `TimeoutStart` | 15초 | 임계값 확장 시작 시점 (`Δt_eff` 기준) |
| `TimeoutEnd` | 60초 | 모든 채굴자 통과 (`Δt_eff` 기준) |
| `VCTFutureTolerance` | 15초 | 미래 타임스탬프 허용 상수 `F` |

`SortitionEligible(output, Δt)`: Δt ≥ TimeoutEnd이면 무조건 통과.

### 타임스탬프 조작 완화 (`VCTFutureTolerance`)

`TimeoutStart` / `TimeoutEnd`는 원시 `Δt = header.Time - parent.Time`이 아닌 **유효 경과 시간** `Δt_eff`를 기준으로 한다:

```
Δt_eff = max(0, Δt - F)    // F = VCTFutureTolerance = 15
```

검증 노드는 `verifyVRFProof`에서 `EffectiveDeltaT(rawDeltaT)`를 호출하여 `Δt_eff`로 정렬 통과 여부를 판정한다. 채굴자가 타임스탬프를 최대 `F`초 앞당겨도 `Δt_eff`는 변하지 않으므로, `F` 이하의 타임스탬프 조작은 타임아웃 자격 확대로 이어지지 않는다.

채굴자가 `t_submit` 대기 후 블록을 제출할 때 사용하는 원시 타임스탬프 조건:

```
header.Time >= parent.Time + t_submit + F
```

`sealer.go`에서 `submitAt = parentTime + delay + VCTFutureTolerance`로 계산된다.

---

## S₀ 잔액 게이트

VCT 블록 제안자는 부모 상태 기준 최소 잔액(S₀)을 보유해야 한다.

- 설정: genesis `vct.minEligibleBalance` (단위: wei)
- 검사 위치: `WriteBlockAndSetHead()` (채굴), `insertChain()` (P2P 동기화)
- 검사 실패 시: 블록 거부 (`consensus.ErrProposerIneligible`)

---

## Daejeon 테스트넷 설정

### ChainConfig (`params/config.go`)

```go
DaejeonChainConfig = &ChainConfig{
    ChainID:             big.NewInt(10399),
    VCTBlock:            big.NewInt(0),   // 블록 0부터 VCT 활성화
    Vct: &VctConfig{
        MinEligibleBalance: 10 WL (= 10 × 10¹⁸ wei),
    },
    // ECCPoW 파라미터 (하드포크 전 구간용)
    ...
}
```

`IsVCT(num *big.Int) bool` — `VCTBlock`이 0이므로 Daejeon에서는 모든 블록이 VCT.  
제네시스 해시: `0xa37bd6...5f32ef`

### VctConfig 구조체

| 필드 | 타입 | 설명 |
|------|------|------|
| `MinEligibleBalance` | `*big.Int` | S₀ (기본값, wei 단위) |
| `S0ForkBlock` | `*big.Int` | S₀ 전환 블록 (옵션) |
| `S0ForkBalance` | `*big.Int` | 전환 후 S₀ 값 (옵션) |

`MinEligibleBalanceAt(blockNum)` — 블록 번호에 따라 적절한 S₀ 반환.

### genesis 파일 (`daejeon-genesis.json`)

```json
{
  "config": {
    "chainId": 10399,
    "vctBlock": 100,
    "vct": { "minEligibleBalance": "10000000000000000000" }
  }
}
```

`vctBlock` 값은 genesis.json에서 설정하며 체인 설정으로 저장된다.

### 부트노드 (`params/bootnodes.go`)

`DaejeonBootnodes` — Daejeon 테스트넷 전용 enode URL 목록.  
`DaejeonGenesisHash` — 제네시스 해시로 네트워크 이름을 `"daejeon"`으로 매핑.

---

## 전체 스택 연결 (Full Node Wiring)

### consensus 인터페이스 추가 (`consensus/consensus.go`)

```go
// ProposerVerifier는 잔액 게이트된 블록 제안자 자격 검증용 선택적 인터페이스 (WIP-6 S₀).
type ProposerVerifier interface {
    VerifyProposerEligibility(chain ChainHeaderReader, header, parent *types.Header, parentState *state.StateDB) error
}
```

VCT 엔진이 이 인터페이스를 구현하며, 부모 상태 로드 직후 블록 처리 전에 호출된다.

### blockchain.go S₀ 게이트 (`core/blockchain.go`)

`WriteBlockAndSetHead()` (채굴 경로):
```go
parentState, err := bc.StateAt(parentHeader.Root)
if err != nil {
    // snap sync 등 부모 상태 없음 → S₀ 건너뜀. ECCPoW + VRF는 여전히 적용.
    log.Debug("WIP-6 S₀ check skipped: parent state unavailable", ...)
} else if err := pv.VerifyProposerEligibility(..., parentState); err != nil {
    return NonStatTy, err
}
```

`insertChain()` (P2P 동기화 경로)에서도 동일한 패턴으로 호출. snap sync 구간에서 `state.New`가 실패하면 `VerifyProposerEligibility` 호출 자체가 발생하지 않는다 (state 에러가 먼저 반환됨).

**snap sync와 S₀**: 부모 상태가 없는 경우 S₀ 검증을 건너뛴다. ECCPoW 유효성과 VRF 증명은 상태 독립적으로 항상 검증되므로, S₀ 게이트 우회만으로 공격자가 얻을 수 있는 이득은 없다.

### VCT 설정 로드 (`core/genesis.go`)

```go
func LoadVctConfig(db ethdb.Database, genesis *Genesis) (*params.VctConfig, error)
```

`eth/backend.go`에서 `LoadVctConfig()` 결과를 `CreateConsensusEngine()`에 전달.  
`DefaultDaejeonGenesisBlock()` — Daejeon 테스트넷 기본 제네시스 블록 반환.

### 엔진 생성 (`eth/ethconfig/config.go`)

```go
func CreateConsensusEngine(..., vctConfig *params.VctConfig, ...) consensus.Engine {
    if vctConfig != nil {
        engine = vct.New(vct.Config{}, notify, noverify)
    } else if eccpowConfig != nil {
        engine = eccpow.New(...)
    }
    return beacon.New(engine)
}
```

### VRF 키 주입 흐름

```
--unlock <coinbase>               (geth flag)
  → KeyStore.Unlock()
  → KeyStore.GetUnlockedKey()     (신규 추가: accounts/keystore/keystore.go)
      └─ ks.unlocked[addr].PrivateKey 반환
  → Ethereum.SetVRFKey(seckey)    (eth/backend.go)
      └─ engine.(vct.VRFKeySetter).SetVRFKey(seckey)
  → ECC.SetVRFKey()               (consensus/vct/algorithm.go)
      └─ ecc.vrfSecKey / vrfPubKey 저장
```

`GetUnlockedKey(a accounts.Account) (*ecdsa.PrivateKey, error)` — 잠금 해제된 계정의 개인키를 반환. 잠금 해제되지 않은 경우 `ErrLocked`.

### LES 경량 클라이언트 (`les/client.go`)

`CreateConsensusEngine` 호출 시 `chainConfig.Vct` 전달. 경량 클라이언트에서도 VCT 헤더 검증 가능.

---

## CLI 플래그 및 네트워크 선택

### `--daejeon` 플래그 (`cmd/utils/flags.go`)

```
--daejeon    Daejeon 테스트넷 (chainID 10399, VCT 합의) 사용
```

- datadir: `~/.worldland/daejeon`
- 부트노드: `DaejeonBootnodes`
- 제네시스: `DefaultDaejeonGenesisBlock()`

### VRF 채굴 시 필수 플래그

```bash
worldland --daejeon --mine --unlock <coinbase> --password <pwfile>
```

`--unlock` 없이 `--mine` 시 블록 100 채굴 시 `VRF key error: unlock the account` 반환.

---

## C 라이브러리 VRF 모듈 (`crypto/secp256k1/libsecp256k1/`)

libsecp256k1에 ECVRF (secp256k1-SHA256-TAI) 모듈을 추가:

| 파일 | 내용 |
|------|------|
| `include/secp256k1_vrf.h` | `secp256k1_vrf_prove`, `secp256k1_vrf_verify`, `secp256k1_vrf_proof_to_hash` API |
| `src/modules/vrf/main_impl.h` | IETF ECVRF 구현 (gamma, c, s 계산) |
| `src/modules/vrf/tests_impl.h` | 라이브러리 내부 벡터 테스트 |
| `src/secp256k1.c` | `#include "modules/vrf/main_impl.h"` 추가 |
| `secp256.go` | CGO 빌드 태그에 `MODULE_VRF` 추가 |

출력: 81바이트 proof (33B gamma point + 16B c scalar + 32B s scalar).

---

## 블록 헤더 직렬화 (`core/types/`)

`gen_header_json.go`, `gen_header_rlp.go`는 코드 생성 파일.  
`VRFProof`, `VRFPublicKey`, `VRFSignature` 필드를 RLP 및 JSON 인코딩에 포함.

- RLP: 필드가 nil이면 빈 바이트열로 인코딩 (레거시 블록과 호환)
- JSON: `vrfProof`, `vrfPublicKey`, `vrfSignature` 키로 hex 인코딩

---

## miner/worker.go 수정 사항

VCT의 진보적 타임아웃으로 인해 `Seal()`이 `header.Time`을 수정할 수 있어 sealHash가 변한다.  
task 조회 시 sealHash 일치 실패를 블록 번호로 폴백:

```go
if !exist {
    // VCT progressive timeout: Seal() may update header.Time/Difficulty,
    // shifting the sealhash. Fall back to block-number lookup.
    for _, t := range w.pendingTasks {
        if t.block.NumberU64() == block.NumberU64() {
            task = t; exist = true; break
        }
    }
}
```

---

## WL 단위 별칭 (`internal/jsre/deps/web3.js`)

JavaScript 콘솔에서 WL 단위 별칭 추가:

| 별칭 | wei 값 |
|------|--------|
| `wl` | 10¹⁸ (= ether) |
| `femtowl` | 10³ |
| `picowl` | 10⁶ |
| `nanowl` | 10⁹ (= gwei) |
| `microwl` | 10¹² |

---

## 파일 구조

```
consensus/vct/
  algorithm.go          ECC 구조체, VRF 키 관리, IsEligibleForBlock
  consensus.go          verifyHeader, verifySeal, verifyVRFProof, verifyMiningSig,
                        legacySealHash, accumulateRewardsLegacy, SealHash
  sealer.go             Seal, mine, mine_seoul, remoteSealer
  vct_secp256k1.go      VRFProve/Verify wrapper, 정렬 함수
  vct_pow.go            VCTVerifyOptimizedDecoding wrapper
  vct_secp256k1_test.go VRF 단위 테스트
  wip6_test.go          WIP-6 통합 테스트

crypto/secp256k1/
  vrf.go                C (libsecp256k1) VRF 래퍼
  vrf_keys.go           DeriveVRFKeys, VRFPubkeyFromSeckey
  vrf_test.go           VRF 암호 속성 테스트
  secp256.go            CGO 빌드 태그 (MODULE_VRF 추가)
  libsecp256k1/         ECVRF C 모듈 (main_impl.h, secp256k1_vrf.h, ...)

accounts/keystore/
  keystore.go           GetUnlockedKey() 추가 — VRF 키 주입용

consensus/
  consensus.go          ProposerVerifier 인터페이스 추가

core/
  blockchain.go         WriteBlockAndSetHead / insertChain S₀ 게이트
  genesis.go            LoadVctConfig, DefaultDaejeonGenesisBlock
  types/block.go        VRFProof, VRFPublicKey, VRFSignature 헤더 필드
  types/gen_header_json.go  (자동 생성) JSON 코덱
  types/gen_header_rlp.go   (자동 생성) RLP 코덱

eth/
  backend.go            LoadVctConfig, SetVRFKey 주입, CreateConsensusEngine 호출
  ethconfig/config.go   CreateConsensusEngine — vctConfig 분기

les/
  client.go             경량 클라이언트 VCT 엔진 연결

miner/
  worker.go             task 조회 번호 폴백 (VCT 타임아웃 sealHash 변경 대응)

cmd/utils/
  flags.go              --daejeon 플래그, 부트노드, datadir 분기

cmd/worldland/
  chaincmd.go           Daejeon 제네시스 선택
  main.go               --daejeon 네트워크 시작 로그

params/
  config.go             DaejeonChainConfig, VctConfig, IsVCT(), MinEligibleBalanceAt()
  bootnodes.go          DaejeonBootnodes, DaejeonGenesisHash

daejeon-genesis.json    Daejeon 테스트넷 제네시스 파일

internal/jsre/deps/
  web3.js               wl/femtowl/picowl/nanowl/microwl 단위 별칭
```
