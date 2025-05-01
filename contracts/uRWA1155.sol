// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IuRWA} from "./interfaces/IuRWA.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";

/// @title uRWA-1155 Token Contract
/// @notice An ERC-1155 token implementation adhering to the IuRWA interface for Real World Assets.
/// @dev Combines standard ERC-1155 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, and asset recall, managed via AccessControl. Represents unique and fungible assets.
contract uRWA1155 is Context, ERC1155, AccessControlEnumerable, IuRWA {
    /// @notice Role identifiers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant RECALL_ROLE = keccak256("RECALL_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    /// @notice Mapping storing the whitelist status for each user address.
    /// @dev True indicates the user is whitelisted and allowed to interact, false otherwise.
    mapping(address => bool) public isWhitelisted;

    /// @notice Emitted when an account's whitelist status is changed.
    /// @param account The address whose status was changed.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    event Whitelisted(address indexed account, bool status);

    /// @notice Error reverted when an operation requires a non-zero address but address(0) was provided.
    error NotZeroAddress();

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-1155 token with a URI and grants all roles
    /// (Admin, Minter, Burner, Recall, Whitelist) to the `initialAdmin`.
    /// @param uri The URI for the token metadata.
    /// @param initialAdmin The address to receive initial administrative and operational roles. Must not be the zero address.
    constructor(string memory uri, address initialAdmin) ERC1155(uri) {
        require(initialAdmin != address(0), NotZeroAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(RECALL_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
    }

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits a {Whitelisted} event upon successful update.
    /// Reverts if `account` is the zero address.
    /// @param account The address whose whitelist status is to be changed. Must not be the zero address.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    function changeWhitelist(address account, bool status) external onlyRole(WHITELIST_ROLE) {
        require(account != address(0), NotZeroAddress());
        isWhitelisted[account] = status;
        emit Whitelisted(account, status);
    }

    /// @notice Safely creates `amount` new tokens of `id` and assigns them to `to`.
    /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    /// Requires `to` to be allowed according to {isUserAllowed}.
    /// Emits a {TransferSingle} event with `operator` set to the caller.
    /// @param to The address that will receive the minted tokens.
    /// @param id The ID of the token to mint.
    /// @param amount The amount of tokens to mint.
    function mint(address to, uint256 id, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(isUserAllowed(to), UserNotAllowed(to));
        _mint(to, id, amount, "");
    }

    /// @notice Destroys `amount` tokens of `id` from the caller's account.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Requires the caller to be allowed according to {isUserAllowed}.
    /// Emits a {TransferSingle} event with `to` set to the zero address.
    /// @param id The ID of the token to burn.
    /// @param amount The amount of tokens to burn.
    function burn(uint256 id, uint256 amount) external onlyRole(BURNER_ROLE) {
        require(isUserAllowed(_msgSender()), UserNotAllowed(_msgSender()));
        _burn(_msgSender(), id, amount);
    }

    /// @notice Takes tokens from one address and transfers them to another, bypassing standard transfer checks.
    /// @dev Implements the {IuRWA-recall} function. Requires the caller to have the `RECALL_ROLE`.
    /// Requires `to` to be allowed according to {isUserAllowed}.
    /// Emits both a {Recalled} event and a standard {TransferSingle} event.
    /// @param from The address from which `amount` is taken.
    /// @param to The address that receives `amount`.
    /// @param tokenId The ID of the token being recalled.
    /// @param amount The amount to recall.
    function recall(address from, address to, uint256 tokenId, uint256 amount) public onlyRole(RECALL_ROLE) {
        require(isUserAllowed(to), UserNotAllowed(to));
        _safeTransferFrom(from, to, tokenId, amount, "");
        emit Recalled(from, to, tokenId, amount);
    }

    /// @notice Checks if a transfer of a specific token is currently possible according to token rules.
    /// @dev Implements the {IuRWA-isTransferAllowed} function for ERC-1155. Checks if `from` has sufficient balance
    /// and if both `from` and `to` are allowed users according to {isUserAllowed}.
    /// @param from The address sending the token. Must be the owner.
    /// @param to The address receiving the token.
    /// @param tokenId The specific token identifier being transferred.
    /// @param amount The amount being transferred.
    /// @return allowed True if the transfer is allowed, false otherwise.
    function isTransferAllowed(address from, address to, uint256 tokenId, uint256 amount) public view virtual override returns (bool allowed) {
        if (balanceOf(from, tokenId) < amount) return false;
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;

        return true;
    }

    /// @notice Checks if a specific user is allowed to interact with the token based on the whitelist.
    /// @dev Implements the {IuRWA-isUserAllowed} function. Returns the status from the {isWhitelisted} mapping.
    /// Does not revert.
    /// @param user The address to check.
    /// @return allowed True if the user is whitelisted, false otherwise.
    function isUserAllowed(address user) public view virtual override returns (bool allowed) {
        return isWhitelisted[user];
    }

    /// @notice Hook that is called before any token transfer, including minting and burning.
    /// @dev Overrides the ERC-1155 `_update` hook. Enforces transfer restrictions based on
    /// {isTransferAllowed} for regular transfers and {isUserAllowed} for minting and burning.
    /// Reverts with {TransferNotAllowed} or {UserNotAllowed} if checks fail.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param ids The array of ids.
    /// @param values The array of amounts being transferred.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal virtual override {
        if (ids.length != values.length) {
            revert ERC1155InvalidArrayLength(ids.length, values.length);
        }

        for (uint256 i = 0; i < ids.length; ++i) {
            if (from != address(0) && to != address(0)) { // Transfer
                require(isTransferAllowed(from, to, ids[i], values[i]), TransferNotAllowed(from, to, ids[i], values[i]));
            }
        }

        if (from == address(0)) { // Mint
            require(isUserAllowed(to), UserNotAllowed(to));
        } else if (to == address(0)) { // Burn --> do we need to check if from isUserAllowed ? 
            require(isUserAllowed(from), UserNotAllowed(from));
        }

        super._update(from, to, ids, values);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IuRWA} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC1155, IERC165) returns (bool) {
        return interfaceId == type(IuRWA).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}