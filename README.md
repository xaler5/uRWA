# uRWA - Universal Real World Asset Standard 
## Reference Implementation

This repository contains Solidity implementations of the **uRWA (Universal Real World Asset)** standard, a minimal interface designed for tokenizing Real World Assets (RWAs). It provides a common ground for regulatory compliance and control features often required for RWAs, while remaining compatible with existing token standards like ERC-20, ERC-721 and ERC-1155.

The canonical ERC-7943 specification and reference assets are maintained in [`ethereum/ERCs`](https://github.com/ethereum/ERCs); this standalone repository mirrors and extends those assets.

**<ins>‼️ Warning: Unaudited Code ‼️</ins>**

**<ins>The smart contracts in this repository are unaudited and are provided for reference and educational purposes only. They have not undergone a formal security audit. Do NOT use this code in a production environment without a thorough professional audit. Use at your own risk.</ins>**

## Overview

The uRWA standard, as defined by ERC-7943, aims to provide essential functionalities for RWAs without imposing excessive complexity. Key features of the **reference implementations** and the ERC-7943 interfaces include:

*   **Whitelisting:** Control which addresses are allowed to send and receive the token (see `canSend` / `canReceive` and the directional whitelists in the reference implementations).
*   **Transfer Control:** Define rules for when transfers are permitted (`canTransfer`).
*   **Asset Freezing:** Control the ability to freeze and unfreeze portions of a user's token balance or specific token IDs (`setFrozenTokens`, `getFrozenTokens`).
*   **ForcedTransfer Functionality:** Allow authorized parties to forcibly transfer tokens, often necessary for regulatory compliance (`forcedTransfer`). The reference implementations use the single-party permissioned model: an authorized forced transfer may bypass ordinary frozen-balance constraints, adjusting the frozen amount before moving the asset when necessary. The permissioned burn paths use the same frozen-state adjustment model.
*   **Access Control:** The reference implementations utilize role-based access control (via OpenZeppelin's `AccessControlEnumerable`) to manage permissions for sensitive actions like minting, burning, forced transfers, managing the whitelist, and changing freeze status.

### Key Interface Elements

ERC-7943 defines three interfaces: `IERC7943Fungible`, `IERC7943NonFungible`, and `IERC7943MultiToken`. The multi-token variant is shown below.

**Functions:**
*   `forcedTransfer(address from, address to, uint256 tokenId, uint256 amount)`: Forcibly moves tokens.
*   `setFrozenTokens(address account, uint256 tokenId, uint256 amount)`: Overwrites the absolute frozen amount for an account and token ID.
*   `getFrozenTokens(address account, uint256 tokenId) returns (uint256 amount)`: Queries the amount of frozen tokens.
*   `canTransfer(address from, address to, uint256 tokenId, uint256 amount) returns (bool allowed)`: Checks if a standard transfer is permissible.
*   `canSend(address account) returns (bool allowed)`: Checks if an account is permitted to send tokens.
*   `canReceive(address account) returns (bool allowed)`: Checks if an account is permitted to receive tokens.

**Events:**
*   `ForcedTransfer(address indexed from, address indexed to, uint256 indexed tokenId, uint256 amount)`: Emitted when tokens are forcibly transferred.
*   `Frozen(address indexed account, uint256 indexed tokenId, uint256 amount)`: Emitted when the freeze status of an account's tokens changes.

**Errors:**
*   `ERC7943CannotSend(address account)`: Reverted if an account is not allowed to send tokens.
*   `ERC7943CannotReceive(address account)`: Reverted if an account is not allowed to receive tokens.
*   `ERC7943CannotTransfer(address from, address to, uint256 tokenId, uint256 amount)`: Reverted if a transfer is not allowed according to internal rules.
*   `ERC7943InsufficientUnfrozenBalance(address account, uint256 tokenId, uint256 amount, uint256 unfrozen)`: Reverted if a transfer attempts to move more tokens than are available (unfrozen).

## Implementations

This repository provides three primary implementations:

1.  **[`uRWA20.sol`](contracts/uRWA20.sol):** An ERC-20 compliant token implementing the `IERC7943Fungible` interface.
2.  **[`uRWA721.sol`](contracts/uRWA721.sol):** An ERC-721 compliant token implementing the `IERC7943NonFungible` interface.
3.  **[`uRWA1155.sol`](contracts/uRWA1155.sol):** An ERC-1155 compliant token implementing the `IERC7943MultiToken` interface.

## EIP

ERC-7943 is Final. For the full specification and rationale, refer to [ERC-7943 on eips.ethereum.org](https://eips.ethereum.org/EIPS/eip-7943) or the local copy: [`EIP-7943.md`](EIP-7943.md).

## Development

This project uses the [Foundry](https://github.com/foundry-rs/foundry) development toolkit.

### Prerequisites

*   [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Setup

1.  **Clone the repository:**
```bash
git clone https://github.com/xaler5/urwa.git
cd urwa
```
2.  **Install dependencies (submodules):**
```bash
forge install
```

### Build

Compile the contracts:

```bash
yarn build
```

### Test

Run the test suite and coverage:

```bash
yarn test
yarn coverage
```

### License

This project is licensed under the MIT License - see the package.json file for details.
