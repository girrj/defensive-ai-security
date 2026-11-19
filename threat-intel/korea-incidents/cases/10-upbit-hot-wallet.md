# 10. Upbit Solana hot-wallet theft (업비트 솔라나 핫월렛 탈취), 2025

About ₩44.5 billion in Solana-network tokens left a crypto exchange's hot wallet for 165 attacker addresses. The exchange said a flaw let someone infer private keys from its wallets' transaction history. It happened on the same date as the exchange's 2019 hack.

| Field | Value |
| --- | --- |
| Date | 27 November 2025, 04:42 KST |
| Sector | Virtual asset service provider (가상자산거래소) |
| Impact | 24 Solana-network tokens worth about ₩44.5 billion at the time (first announced as ₩54 billion). About ₩2.3 billion frozen. Customers reimbursed from company funds |
| Initial access | Not published. The company named a wallet weakness that allowed private-key inference from transaction data |
| Related CVEs | None |
| Attribution | Authorities reportedly suspect Lazarus. Not officially confirmed |
| Public IOCs | Destination wallet addresses circulated on chain; not reproduced here |

## What happened

1. At 04:42 the exchange saw withdrawals from its Solana hot wallet to addresses it had not designated.
2. Deposits and withdrawals were suspended and remaining assets moved to cold storage.
3. The company reported to KISA and the financial authorities, apologized, and said it had found and fixed a weakness that let wallet addresses' private keys be inferred from the wallet's transaction history. The wallet system was rebuilt.
4. Authorities examined the possibility of Lazarus involvement, noting the 2019 theft from the same exchange on the same date.

## Why it is hard to defend

Blockchain transactions are final. Detection has to happen **before signing**, on the systems that build and sign withdrawals, or the money is gone. The control points are key generation (randomness, derivation), the signing service, and withdrawal policy (limits, allow-lists, delays, human approval).

## ATT&CK mapping

| Tactic | Technique | Observed as |
| --- | --- | --- |
| Credential Access | T1552.004 Private Keys | Private keys derived from transaction data |
| Impact | T1657 Financial Theft | Unauthorized withdrawals |
| Exfiltration | — | Funds split across 165 addresses |

## Detect it with this repo

| Layer | Detection |
| --- | --- |
| Hunting | [Hot-wallet withdrawal anomalies](../hunting.md#hot-wallet-withdrawals) |
| Encyclopedia | Hot wallet and key custody (planned, see the [encyclopedia list](../../../encyclopedia/README.md#5-techniques-위협-영역별-방어--techniques)) |

## Lessons for SOC and CERT

- **Treat signing infrastructure as tier-zero.** Monitor it like domain controllers: who can request a signature, from where, for how much.
- **Policy before signature**: velocity limits, destination allow-lists and time delays for large hot-wallet transfers.
- **Test key generation and derivation code** with outside review. A cryptographic weakness can be invisible to every other control.
- **Keep the hot wallet small.** The exposure is what is online.

## Sources

- [Boan News: CEO apology, private-key inference flaw, Lazarus suspected](https://m.boannews.com/html/detail.html?idx=140625)
- [MTN: 04:42 detection, 24 tokens, hot wallet](https://news.mtn.co.kr/news-detail/2025112814572160199)
- [Kyunghyang: 165 destination addresses, move to cold wallet](https://www.khan.co.kr/article/202511272058005/)
- [Blockmedia: amount corrected to ₩44.5 billion](https://www.blockmedia.co.kr/archives/1011940)
