# SignalHash Airdrop Smart Contract

Open-source TON smart contract used for SignalHash reward distributions.

`PayoutVault` keeps reward allocations on-chain, verifies Ed25519-signed
instructions, and lets eligible users withdraw their full allocation to a TON
wallet.

## Links

|     | Resource                                                                                                                      |
| --- | ----------------------------------------------------------------------------------------------------------------------------- |
| 🌐  | **Website:** [signalhash.io](https://signalhash.io)                                                                           |
| 📚  | **Withdrawal guide:** [How to withdraw TON airdrops](https://signalhash.io/tutorials/withdraw-ton-airdrops)                   |
| 🏆  | **Weekly rewards:** [Current rewards and payout guide](https://signalhash.io/tutorials/weekly-rewards-current-guide)          |
| 🔍  | **Explorer:** [View the payout contract on Tonviewer](https://tonviewer.com/EQCCcS2yadUpVmGxtufIVAyKVQh7rnxWHlTJ7LlGH1Q-p_eu) |

## Mainnet Contract

```text
EQCCcS2yadUpVmGxtufIVAyKVQh7rnxWHlTJ7LlGH1Q-p_eu
```

Always verify the address against the official SignalHash website before
interacting with the contract.

## How It Works

-   The contract owner submits one or more reward allocations.
-   Every allocation update must also carry a valid master-key signature.
-   Withdrawal instructions are signed, time-limited, and bound to a recipient
    wallet.
-   Hash-chained state prevents signed operations from being replayed or applied
    out of order.
-   The vault keeps a minimum TON reserve for storage rent.
-   The owner can rotate the master public key through an authenticated,
    hash-chained operation.

Allocations are indexed by a 256-bit user identifier. The contract does not
store usernames or other personal profile data.

## Development

### Requirements

-   Node.js 18 or newer
-   npm

### Install and test

```bash
npm install
npm run build
npm test
```

Useful commands:

```bash
npm run fmt
npm run lint
```

## Project Structure

```text
sources/
├── contest.tact        # PayoutVault contract
├── contest.spec.ts     # Sandbox test suite
└── contest.deploy.ts   # Deployment helper

tact.config.json        # Tact compiler configuration
```

Generated wrappers and contract artifacts are written to `sources/output/`.

## Security

Smart contracts can hold real funds. Review the code, run the complete test
suite, and test deployments on TON testnet before using this project in
production. Never commit owner credentials or master signing keys.

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE).
