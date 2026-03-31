# @open-wallet-standard/viem

Viem account adapter for the [Open Wallet Standard](https://openwallet.sh).

```bash
npm install @open-wallet-standard/viem viem
```

```typescript
import { owsToViemAccount } from "@open-wallet-standard/viem";
const account = owsToViemAccount("my-wallet");
```

Works with any viem-based project: mppx, wagmi, x402, etc.
