# uRWA - Universal Real World Asset Standard 
## Reference Implementation

This repository contains Solidity implementations of the **uRWA (Universal Real World Asset)** standard, a minimal interface designed for tokenizing Real World Assets (RWAs). It provides a common ground for regulatory compliance and control features often required for RWAs, while remaining compatible with existing token standards like ERC-20, ERC-721 and ERC-1155.

## Overview

The uRWA standard aims to provide essential functionalities for RWAs without imposing excessive complexity. Key features of the **reference implementation** include:

*   **Whitelisting:** Control which addresses are allowed to interact with the token (`isUserAllowed`, `changeWhitelist`).
*   **Transfer Control:** Define rules for when transfers are permitted (`isTransferAllowed`).
*   **ForceTransfer Functionality:** Allow authorized parties to forcibly transfer tokens, often necessary for regulatory compliance (`forceTransfer`).
*   **Access Control:** Utilizes role-based access control (via OpenZeppelin's `AccessControlEnumerable`) to manage permissions for sensitive actions like minting, burning, forced transfers, and managing the whitelist.

## Implementations

This repository provides three primary implementations:

1.  **[`uRWA-20.sol`](/home/xaler/workspace/uRWA/contracts/uRWA-20.sol):** An ERC-20 compliant token implementing the `IERC7943` interface.
2.  **[`uRWA-721.sol`](/home/xaler/workspace/uRWA/contracts/uRWA-721.sol):** An ERC-721 compliant token implementing the `IERC7943` interface.
3.  **[`uRWA-1155.sol`](/home/xaler/workspace/uRWA/contracts/uRWA-1155.sol):** An ERC-1155 compliant token implementing the `IERC7943` interface.

## EIP Draft

For a detailed specification and rationale behind the uRWA standard, please refer to the draft EIP document: [`EIP-UniversalRWA.md`](/home/xaler/workspace/uRWA/EIP-UniversalRWA.md).

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