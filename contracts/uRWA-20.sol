// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IuRWA} from "./interfaces/IuRWA.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";

/// @title uRWA-20 Token Contract
/// @notice An ERC-20 token implementation adhering to the IuRWA interface for Real World Assets.
/// @dev Combines standard ERC-20 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, and asset recall, managed via AccessControl.
contract uRWA20 is Context, ERC20, AccessControlEnumerable, IuRWA {
    /// @notice Role identifiers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant RECALL_ROLE = keccak256("RECALL_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    /// @notice Mapping storing the whitelist status for each user address.
    /// @dev True indicates the user is whitelisted and allowed to interact, false otherwise.
    mapping(address user => bool whitelisted) public isWhitelisted;

    /// @notice Emitted when an account's whitelist status is changed.
    /// @param account The address whose status was changed.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    event Whitelisted(address indexed account, bool status);

    /// @notice Error reverted when an operation requires a non-zero address but address(0) was provided.
    error NotZeroAddress();

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-20 token with name and symbol, and grants all roles
    /// (Admin, Minter, Burner, Recall, Whitelist) to the `initialAdmin`.
    /// @param name The name of the token.
    /// @param symbol The symbol of the token.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    constructor(string memory name, string memory symbol, address initialAdmin) ERC20(name, symbol) {
        require(initialAdmin != address(0), NotZeroAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(RECALL_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
    }

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits a {Whitelisted} event.
    /// @param account The address whose whitelist status is to be changed. Must not be the zero address.
    /// @param status The new whitelist status (true or false).
    function changeWhitelist(address account, bool status) external onlyRole(WHITELIST_ROLE) {
        require(account != address(0), NotZeroAddress());
        isWhitelisted[account] = status;
        emit Whitelisted(account, status);
    }

    /// @notice Creates `amount` new tokens and assigns them to `to`.
    /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    /// Requires `to` to be allowed according to {isUserAllowed}.
    /// Emits a {Transfer} event with `from` set to the zero address.
    /// @param to The address that will receive the minted tokens.
    /// @param amount The amount of tokens to mint.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @notice Destroys `amount` tokens from the caller's account.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Requires the caller to be allowed according to {isUserAllowed}.
    /// Emits a {Transfer} event with `to` set to the zero address.
    /// @param amount The amount of tokens to burn.
    function burn(uint256 amount) external onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), amount);
    }

    /// @notice Takes tokens from one address and transfers them to another, bypassing standard transfer checks.
    /// @dev Implements the {IuRWA-recall} function. Requires the caller to have the `RECALL_ROLE`.
    /// Requires `to` to be allowed according to {isUserAllowed}.
    /// Directly updates balances using the parent ERC20 `_update` function.
    /// Emits both a {Recalled} event and a standard {Transfer} event.
    /// @param from The address from which `amount` is taken.
    /// @param to The address that receives `amount`.
    /// @param amount The amount to recall.
    function recall(address from, address to, uint256 amount) external onlyRole(RECALL_ROLE) {
        require(isUserAllowed(to), UserNotAllowed(to));
        // Directly update balances, bypassing overridden _update
        super._update(from, to, amount);
        emit Recalled(from, to, amount);
    }

    /// @notice Checks if a transfer is currently possible according to token rules.
    /// @dev Implements the {IuRWA-isTransferAllowed} function. Checks if `from` has sufficient balance
    /// and if both `from` and `to` are allowed users according to {isUserAllowed}.
    /// Does not revert.
    /// @param from The address sending tokens.
    /// @param to The address receiving tokens.
    /// @param amount The amount being transferred.
    /// @return allowed True if the transfer is allowed, false otherwise.
    function isTransferAllowed(address from, address to, uint256 amount) public virtual view returns (bool allowed) {
        if (balanceOf(from) < amount) return false;
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;

        return true;
    }

    /// @notice Checks if a specific user is allowed to interact with the token based on the whitelist.
    /// @dev Implements the {IuRWA-isUserAllowed} function. Returns the status from the {isWhitelisted} mapping.
    /// Does not revert.
    /// @param user The address to check.
    /// @return allowed True if the user is whitelisted, false otherwise.
    function isUserAllowed(address user) public virtual view returns (bool allowed) {
        if (!isWhitelisted[user]) return false;
        
        return true;
    }

    /// @notice Hook that is called before any token transfer, including minting and burning.
    /// @dev Overrides the ERC20 `_update` hook. Enforces transfer restrictions based on
    /// {isTransferAllowed} for regular transfers and {isUserAllowed} for minting and burning.
    /// Reverts with {TransferNotAllowed} or {UserNotAllowed} if checks fail.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param value The amount being transferred.
    function _update(address from, address to, uint256 value) internal virtual override {
        if (from != address(0) && to != address(0)) { // Transfer
            require(isTransferAllowed(from, to, value), TransferNotAllowed(from, to, value));
        } else if (from == address(0)) { // Mint
            require(isUserAllowed(to), UserNotAllowed(to));
        } else { // Burn --> do we need to check if from isUserAllowed ? 
            require(isUserAllowed(from), UserNotAllowed(from));
        }

        super._update(from, to, value);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IuRWA} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, IERC165) returns (bool) {
        return interfaceId == type(IuRWA).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}