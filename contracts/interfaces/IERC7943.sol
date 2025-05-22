// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title Interface for the ERC-7943 - uRWA Token
/// @notice Defines the public functions of the uRWA token.
/// When interacting with specific token standards:
/// - For ERC-721 like (non-fungible) tokens 'amount' parameters typically represent a single token (i.e., 1).
/// - For ERC-20 like (fungible) tokens, 'tokenId' parameters are generally not applicable and should be set to 0.
interface IERC7943 is IERC165 {
    /// @notice Emitted when tokens are taken from one address and transferred to another.
    /// @param from The address from which tokens were taken.
    /// @param to The address to which seized tokens were transferred.
    /// @param tokenId The ID of the token being transferred.
    /// @param amount The amount seized.
    event ForcedTransfer(address indexed from, address indexed to, uint256 tokenId, uint256 amount);

    /// @notice Emitted when a specific amount of a token ID is frozen/unfrozen for a user.
    /// @param user The address of the user whose tokens are being frozen.
    /// @param tokenId The ID of the token being frozen.
    /// @param amount The amount of tokens frozen (amount > 0) or unfrozen (amount < 0).
    event FreezeStatusChange(address indexed user, uint256 indexed tokenId, int256 amount);

    /// @notice Error reverted when a user is not allowed to interact. 
    /// @param account The address of the user which is not allowed for interactions.
    error ERC7943NotAllowedUser(address account);

    /// @notice Error reverted when a transfer is not allowed due to restrictions in place.
    /// @param from The address from which tokens are being transferred.
    /// @param to The address to which tokens are being transferred.
    /// @param tokenId The ID of the token being transferred. 
    /// @param amount The amount being transferred.
    error ERC7943NotAllowedTransfer(address from, address to, uint256 tokenId, uint256 amount);

    /// @notice Error reverted when a transfer is attempted from `user` but the `amount` is bigger than available (unfrozen) tokens.
    /// @param user The address holding the tokens.
    /// @param tokenId The ID of the token being transferred. 
    /// @param amount The amount being transferred.
    /// @param available The amount of tokens that are available to transfer.
    error ERC7943NotAvailableAmount(address user, uint256 tokenId, uint256 amount, uint256 available);

    /// @notice Takes tokens from one address and transfers them to another.
    /// @dev Requires specific authorization. Used for regulatory compliance or recovery scenarios.
    /// It should skip frozen status validations.
    /// @param from The address from which `amount` is taken.
    /// @param to The address that receives `amount`.
    /// @param tokenId The ID of the token being transferred.
    /// @param amount The amount to force transfer.
    function forceTransfer(address from, address to, uint256 tokenId, uint256 amount) external;

    /// @notice Changes the freezing status of an `user` asset corresponding to specified `tokenId`.
    /// It can increase the amount of frozen assets (`amount` > 0) or decrease it (`amount` < 0).
    /// @dev Requires specific authorization. Frozen tokens cannot be transferred by the user.
    /// @param user The address of the user whose tokens are to be frozen/unfrozen.
    /// @param tokenId The ID of the token to freeze/unfreeze.
    /// @param amount The amount of tokens to freeze/unfreeze.
    function changeFreezeStatus(address user, uint256 tokenId, int256 amount) external;

    /// @notice Checks the frozen status of a specific token ID.
    /// @param user The address of the user.
    /// @param tokenId The ID of the token.
    /// @return result The amount >= 0 of the token ID currently frozen for the user for ERC-20 and ERC-1155 tokens, 1 or 0 for ERC-721.
    function freezeStatus(address user, uint256 tokenId) external view returns (uint256 result);

    /// @notice Checks if a transfer is currently possible according to token rules. It enforces validations on the frozen tokens.
    /// @dev This may involve checks like allowlists, blocklists, transfer limits etc.
    /// @param from The address sending tokens.
    /// @param to The address receiving tokens. 
    /// @param tokenId The ID of the token being transferred.
    /// @param amount The amount being transferred.
    /// @return allowed True if the transfer is allowed, false otherwise.
    function isTransferAllowed(address from, address to, uint256 tokenId, uint256 amount) external view returns (bool allowed);

    /// @notice Checks if a specific user is allowed to interact with the token.
    /// @dev This is often used for allowlist/KYC checks.
    /// @param user The address to check.
    /// @return allowed True if the user is allowed, false otherwise.
    function isUserAllowed(address user) external view returns (bool allowed);
}