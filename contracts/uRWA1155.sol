// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC7943} from "./interfaces/IERC7943.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC1155Utils} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Utils.sol";

/// @title uRWA-1155 Token Contract
/// @notice An ERC-1155 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-1155 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers and freezing. Managed via AccessControl. Represents both unique and fungible assets.
contract uRWA1155 is Context, ERC1155, AccessControlEnumerable, IERC7943 {
    /// @notice Role identifiers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    /// @notice Mapping storing the whitelist status for each user address.
    /// @dev True indicates the user is whitelisted and allowed to interact, false otherwise.
    mapping(address => bool) public isWhitelisted;

    /// @notice Mapping storing the freezing status of assets for each user address.
    /// @dev It gives the amount of tokens corresponding to a `tokenId` that are frozen in `user` wallet.
    mapping(address user => mapping(uint256 tokenId => uint256 amount)) internal _frozenTokens;

    /// @notice Emitted when an account's whitelist status is changed.
    /// @param account The address whose status was changed.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    event Whitelisted(address indexed account, bool status);

    /// @notice Error reverted when an operation requires a non-zero address but address(0) was provided.
    error NotZeroAddress();

    /// @notice Error reverted when an operation requires a non-zero amount but 0 was provided.
    error NotZeroAmount();

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-1155 token with a URI and grants all roles
    /// (Admin, Minter, Burner, Enforcer, Whitelist) to the `initialAdmin`.
    /// @param uri The URI for the token metadata.
    /// @param initialAdmin The address to receive initial administrative and operational roles. Must not be the zero address.
    constructor(string memory uri, address initialAdmin) ERC1155(uri) {
        require(initialAdmin != address(0), NotZeroAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(ENFORCER_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
    }

    /// @inheritdoc IERC7943
    function isTransferAllowed(address from, address to, uint256 tokenId, uint256 amount) public view virtual override returns (bool allowed) {
        if (balanceOf(from, tokenId) < amount) return false;
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;
        if (amount > balanceOf(from, tokenId) - _frozenTokens[from][tokenId]) return false;
        return true;
    }

    /// @inheritdoc IERC7943
    function isUserAllowed(address user) public view virtual override returns (bool allowed) {
        if (!isWhitelisted[user]) return false;
        
        return true;
    }

    /// @inheritdoc IERC7943
    function getFrozen(address user, uint256 tokenId) external view returns (uint256 amount) {
        amount = _frozenTokens[user][tokenId];
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
        _mint(to, id, amount, "");
    }

    /// @notice Destroys `amount` tokens of `id` from the caller's account.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Emits a {TransferSingle} event with `to` set to the zero address.
    /// @param id The ID of the token to burn.
    /// @param amount The amount of tokens to burn.
    function burn(uint256 id, uint256 amount) external onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), id, amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`
    function setFrozen(address user, uint256 tokenId, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(amount <= balanceOf(user, tokenId), ERC1155InsufficientBalance(user, balanceOf(user,tokenId), amount, tokenId));
        
        _frozenTokens[user][tokenId] = amount;        

        emit Frozen(user, tokenId, amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`.
    function forceTransfer(address from, address to, uint256 tokenId, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(isUserAllowed(to), ERC7943NotAllowedUser(to));

        // Reimplementing _safeTransferFrom to avoid the check on _update
        if (to == address(0)) {
            revert ERC1155InvalidReceiver(address(0));
        }
        if (from == address(0)) {
            revert ERC1155InvalidSender(address(0));
        }

        _excessFrozenUpdate(from, tokenId, amount);

        uint256[] memory ids = new uint256[](1);
        uint256[] memory values = new uint256[](1);
        ids[0] = tokenId;
        values[0] = amount;

        super._update(from, to, ids, values);
        
        if (to != address(0)) {
            address operator = _msgSender();
            if (ids.length == 1) {
                uint256 id = ids[0];
                uint256 value = values[0];
                ERC1155Utils.checkOnERC1155Received(operator, from, to, id, value, "");
            } else {
                ERC1155Utils.checkOnERC1155BatchReceived(operator, from, to, ids, values, "");
            }
        } 

        emit ForcedTransfer(from, to, tokenId, amount);
    }

    function _excessFrozenUpdate(address user, uint256 tokenId, uint256 amount) internal {
        uint256 unfrozenBalance = balanceOf(user, tokenId) - _frozenTokens[user][tokenId];
        if(amount > unfrozenBalance && amount <= balanceOf(user, tokenId)) { 
            // Protect from underflow: if amount > balanceOf(user) the call will revert in super._update with insufficient balance error
            _frozenTokens[user][tokenId] -= amount - unfrozenBalance; // Reduce by excess amount
            emit Frozen(user, tokenId, _frozenTokens[user][tokenId]);
        }
    }

    /// @notice Hook that is called before any token transfer, including minting and burning.
    /// @dev Overrides the ERC-1155 `_update` hook. Enforces transfer restrictions based on
    /// {isTransferAllowed} for regular transfers and {isUserAllowed} for minting.
    /// Reverts with {ERC7943NotAllowedTransfer}, {ERC7943NotAllowedUser}, {ERC7943InsufficientUnfrozenBalance} or any of the base
    /// token errors if checks fail.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param ids The array of ids.
    /// @param values The array of amounts being transferred.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal virtual override {
        if (ids.length != values.length) {
            revert ERC1155InvalidArrayLength(ids.length, values.length);
        }

        if (from != address(0) && to != address(0)) { // Transfer
            for (uint256 i = 0; i < ids.length; ++i) {
                uint256 id = ids[i];
                uint256 value = values[i];
                uint256 unfrozenBalance = balanceOf(from, id) - _frozenTokens[from][id];

                require(value <= balanceOf(from, id), ERC1155InsufficientBalance(from, balanceOf(from, id), value, id));
                require(value <= unfrozenBalance, ERC7943InsufficientUnfrozenBalance(from, id, value, unfrozenBalance));
                require(isTransferAllowed(from, to, id, value), ERC7943NotAllowedTransfer(from, to, id, value));
            }
        }

        if (from == address(0)) { // Mint 
            require(isUserAllowed(to), ERC7943NotAllowedUser(to));
        } else if (to == address(0)) { // Burn
            for (uint256 j = 0; j < ids.length; ++j) {
                _excessFrozenUpdate(from, ids[j], values[j]);
            }
        }

        super._update(from, to, ids, values);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IERC-7943} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC1155, IERC165) returns (bool) {
        return interfaceId == type(IERC7943).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}
