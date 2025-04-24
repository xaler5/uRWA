// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title Interface for the uRWA Token
/// @notice Defines the public functions of the uRWA token.
interface IuRWA is IERC165 {
    /// @notice Emitted when tokens are taken from one address and transferred to another.
    /// @param from The address from which tokens were taken.
    /// @param to The address to which seized tokens were transferred.
    /// @param value The value seized.
    event Recalled(address indexed from, address indexed to, uint256 value);

    /// @notice Error reverted when a user is not allowed to interact.
    /// @param account The address of the user which is not allowed for interactions.
    error UserNotAllowed(address account);

    /// @notice Error reverted when a transfer is not allowed due to restrictions in place.
    /// @param from The address from which tokens are being transferred.
    /// @param to The address to which tokens are being transferred.
    /// @param value The value being transferred.    
    error TransferNotAllowed(address from, address to, uint256 value);

    /// @notice Takes tokens from one address and transfers them to another.
    /// @dev Requires specific authorization. Used for regulatory compliance or recovery scenarios.
    /// @param from The address from which `value` is taken.
    /// @param to The address that receives `value`.
    /// @param value The value to recall.
    function recall(address from, address to, uint256 value) external;

    /// @notice Checks if a transfer is currently possible according to token rules and registered plugins.
    /// @dev This may involve checks like allowlists, blocklists, transfer limits, etc.
    /// @param from The address sending tokens.
    /// @param to The address receiving tokens.
    /// @param value The value being transferred.
    /// @return allowed True if the transfer is allowed, false otherwise.
    function isTransferAllowed(address from, address to, uint256 value) external view returns (bool allowed);

    /// @notice Checks if a specific user is allowed to interact with the token.
    /// @dev This is often used for allowlist/KYC checks.
    /// @param user The address to check.
    /// @return allowed True if the user is allowed, false otherwise.
    function isUserAllowed(address user) external view returns (bool allowed);
}