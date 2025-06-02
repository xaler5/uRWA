# uRWA - Universal Real World Asset Standard 
## Reference Implementation

This repository contains Solidity implementations of the **uRWA (Universal Real World Asset)** standard, a minimal interface designed for tokenizing Real World Assets (RWAs). It provides a common ground for regulatory compliance and control features often required for RWAs, while remaining compatible with existing token standards like ERC-20, ERC-721 and ERC-1155.

**<ins>‼️ Warning: Unaudited Code ‼️</ins>**

**<ins>The smart contracts in this repository are unaudited and are provided for reference and educational purposes only. They have not undergone a formal security audit. Do NOT use this code in a production environment without a thorough professional audit. Use at your own risk.</ins>**

## Overview

The uRWA standard, as defined by `IERC7943`, aims to provide essential functionalities for RWAs without imposing excessive complexity. Key features of the **reference implementation** and the `IERC7943` interface include:

*   **Whitelisting:** Control which addresses are allowed to interact with the token (see `isUserAllowed` from `IERC7943` and `changeWhitelist` in reference implementations).
*   **Transfer Control:** Define rules for when transfers are permitted (`isTransferAllowed`).
*   **Asset Freezing:** Control the ability to freeze and unfreeze portions of a user's token balance or specific token IDs (`setFrozen`, `getFrozen`).
*   **ForceTransfer Functionality:** Allow authorized parties to forcibly transfer tokens, often necessary for regulatory compliance (`forceTransfer`). The reference implementation skips freezing checks and adjust freezing status accordingly (same for burning functionality).
*   **Access Control:** The reference implementations utilize role-based access control (via OpenZeppelin's `AccessControlEnumerable`) to manage permissions for sensitive actions like minting, burning, forced transfers, managing the whitelist, and changing freeze status.

### Key Interface Elements (`IERC7943`)

The `IERC7943` interface defines the following core components:

**Functions:**
*   `forceTransfer(address from, address to, uint256 tokenId, uint256 amount)`: Forcibly moves tokens.
*   `setFrozen(address user, uint256 tokenId, uint256 amount)`: Modifies the amount of frozen tokens for a user.
*   `getFrozen(address user, uint256 tokenId) returns (uint256 amount)`: Queries the amount of frozen tokens.
*   `isTransferAllowed(address from, address to, uint256 tokenId, uint256 amount) returns (bool allowed)`: Checks if a standard transfer is permissible.
*   `isUserAllowed(address user) returns (bool allowed)`: Checks if a user is permitted to interact with the token.

**Events:**
*   `ForcedTransfer(address indexed from, address indexed to, uint256 tokenId, uint256 amount)`: Emitted when tokens are forcibly transferred.
*   `Frozen(address indexed user, uint256 indexed tokenId, uint256 indexed previousAmount, uint256 newAmount);`: Emitted when the freeze status of a user's tokens changes.

**Errors:**
*   `ERC7943NotAllowedUser(address account)`: Reverted if a user is not allowed for an interaction.
*   `ERC7943NotAllowedTransfer(address from, address to, uint256 tokenId, uint256 amount)`: Reverted if a transfer is not permitted by current rules.
*   `ERC7943InsufficientUnfrozenBalance(address user, uint256 tokenId, uint256 amount, uint256 available)`: Reverted if a transfer attempts to move more tokens than are available (unfrozen).

## Implementations

This repository provides three primary implementations:

1.  **[`uRWA20.sol`](/home/xaler/workspace/uRWA/contracts/uRWA20.sol):** An ERC-20 compliant token implementing the `IERC7943` interface.
2.  **[`uRWA721.sol`](/home/xaler/workspace/uRWA/contracts/uRWA721.sol):** An ERC-721 compliant token implementing the `IERC7943` interface.
3.  **[`uRWA1155.sol`](/home/xaler/workspace/uRWA/contracts/uRWA1155.sol):** An ERC-1155 compliant token implementing the `IERC7943` interface.

## EIP Draft

For a detailed specification and rationale behind the uRWA standard, please refer to the draft EIP document: [`EIP-UniversalRWA.md`](/home/xaler/workspace/uRWA/EIP-UniversalRWA.md) (which corresponds to `IERC7943`).

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