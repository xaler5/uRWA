---
title: uRWA - Universal Real World Asset Interface
description: A minimal standard interface for regulated assets, targeting the broad spectrum of RWAs.
author: Dario Lo Buglio (@xaler5)
discussions-to: <URL of forum discussion, GitHub issue, etc.>
status: Draft
type: Standards Track
category: ERC
created: 2025-04-27
requires: EIP-165
---

## Abstract

This EIP proposes "Universal RWA" (uRWA) standard, a minimal interface for both ERC-20 and ERC-721 based tokens, meant to be the primitive for the different classes of Real World Assets. It defines essential functions and events for regulatory compliance and enforcement actions common to RWAs.

## Motivation

The tokenization of Real World Assets introduces requirements often absent in purely digital assets, such as regulatory compliance checks, nuanced transfer controls, and potential enforcement actions. Existing token standards, primarily ERC-20 and ERC-721, lack the inherent structure to address these needs directly within the standard itself.

Attempts at defining universal RWA standards historically imposed unnecessary complexity and gas overhead for simpler use cases that do not require the full spectrum of features like granular role-based access control, mandatory on-chain whitelisting, specific on-chain identity solutions or metadata handling solutions mandated by the standard.

The broad spectrum of RWA classes inherently suggests the need to move away from a one-size-fits-all solution. With the purpose in mind of defining an EIP for it, a minimalistic approach, unopinionated features list and maximally compatible design should be kept in mind.

The uRWA standard seeks a more refined balance by defining an essential interface, `IuRWA`, establishing a common ground for interaction regarding compliance and control, without dictating the underlying implementation mechanisms. This allows core token implementations (like ERC-20 or ERC-721) to remain lean while providing standard functions for RWA-specific interactions.

The final goal is to build composable DeFi around RWAs, providing the same interface when dealing with compliance and regulation.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

**1. uRWA Interface (`IuRWA.sol`)**

*   Defines the standard interface for an uRWA token contract.
*   MUST inherit `IERC165`.
*   MUST declare the following functions:
    *   `recall(address from, address to, uint256 value) public`
    *   `isTransferAllowed(address from, address to, uint256 value) public view returns (bool allowed)`
    *   `isUserAllowed(address user) public view returns (bool allowed)`
*   MUST define the following event:
    *   `Recalled(address indexed from, address indexed to, uint256 value)`
*   MUST define the following errors:
    *   `UserNotAllowed(address account)`
    *   `TransferNotAllowed(address from, address to, uint256 value)`
*   Implementations of this interface (e.g., an ERC-20 or ERC-721 contract) SHOULD also implement the necessary functions of their chosen base standard (e.g., `IERC20Metadata`, `IERC721Metadata`).
*   Implementations MUST ensure their internal transfer logic (e.g., within `_update`, `_transfer`, `_mint`, `_burn`) respects the boolean outcomes of `isUserAllowed` and `isTransferAllowed`. Transfers, mints, or burns MUST NOT proceed if these checks indicate the action is disallowed according to the contract's specific policy.
*   Implementations MUST restrict access to sensitive functions like `recall` using an appropriate access control mechanism (e.g., `onlyOwner`, Role-Based Access Control). The specific mechanism is NOT mandated by this interface standard.
*   The `recall` function implementation MUST directly manipulate balances or ownership to transfer the asset (`value` interpreted as amount for ERC-20, tokenId for ERC-721) from `from` to `to` either by transfering or burning from `from` and minting to `to`. It MUST perform necessary checks (e.g., sufficient balance/ownership) and MUST emit both the standard `Transfer` event (from the base ERC standard) and the `Recalled` event. It SHOULD bypass standard transfer validation logic, including checks enforced by `isTransferAllowed` and `isUserAllowed(to)`.
*   The `isUserAllowed` and `isTransferAllowed` functions provide views into the implementing contract's compliance and transfer policy logic. The exact implementation of these checks (e.g., internal allowlist, external calls, complex logic) is NOT mandated by this interface standard. These two functions MUST NOT revert.

## Rationale

*   **Minimalism:** Defines only the essential functions (`recall`, `isUserAllowed`, `isTransferAllowed`) and associated events/errors needed for common RWA compliance and control patterns, avoiding mandated complexity.
*   **Flexibility:** Provides standard view functions (`isUserAllowed`, `isTransferAllowed`) for compliance checks without dictating *how* those checks are implemented internally by the token contract. This allows diverse compliance strategies.
*   **Compatibility:** Designed as an interface layer compatible with existing base standards like ERC-20 and ERC-721. Implementations inherit `IuRWA` alongside their base standard interface.
*   **RWA Essential:** Includes `recall` as a standard function, acknowledging its importance for regulatory enforcement in the RWA space, distinct from standard transfers. Mandates access control for this sensitive function.
*   **EIP-165:** Ensures implementing contracts can signal support for this interface.

As an example, a Uniswap v4 pool can integrate with uRWA ERC-20 tokens by calling `isUserAllowed` or `isTransferAllowed` within its before/after hooks to handle these assets in a compliant manner. Users can then expand these tokens with additional features to fit the specific needs of individual asset types, either with on-chain identity systems, historical balances tracking for dividend distributions etc...

## Backwards Compatibility

This EIP defines a new interface standard and does not alter existing ones like ERC-20 or ERC-721. Standard wallets and explorers can interact with the base ERC-20/ERC-721 functionality of implementing contracts, subject to the rules enforced by that contract's implementation of `isUserAllowed` and `isTransferAllowed`. Full support for the `IuRWA` functions requires explicit integration.

## Security Considerations

*   **Access Control for `recall`:** The security of the mechanism chosen by the implementer to restrict access to the `recall` function is paramount. Unauthorized access could lead to asset theft. Secure patterns (multisig, timelocks) are highly recommended.
*   **Implementation Logic:** The security and correctness of the *implementation* behind `isUserAllowed` and `isTransferAllowed` are critical. Flaws in this logic could bypass intended transfer restrictions or incorrectly block valid transfers.
*   **Standard Contract Security:** Implementations MUST adhere to general smart contract security best practices (reentrancy guards where applicable, checks-effects-interactions, etc.).

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).