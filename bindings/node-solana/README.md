# @open-wallet-standard/solana

Solana Keypair adapter for the [Open Wallet Standard](https://openwallet.sh).

```bash
npm install @open-wallet-standard/solana @solana/web3.js
```

```typescript
import { owsToSolanaKeypair } from "@open-wallet-standard/solana";
const keypair = owsToSolanaKeypair("my-wallet");
```

Works with any Solana project: Anchor, spl-token, Metaplex, etc.
