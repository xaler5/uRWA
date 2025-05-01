// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IuRWA} from "./interfaces/IuRWA.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721Utils} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Utils.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";

/// @title uRWA-721 Token Contract
/// @notice An ERC-721 token implementation adhering to the IuRWA interface for Real World Assets.
/// @dev Combines standard ERC-721 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, and asset recall, managed via AccessControl. Represents unique assets.
contract uRWA721 is Context, ERC721, AccessControlEnumerable, IuRWA {
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
    /// @dev Initializes the ERC-721 token with name and symbol, and grants all roles
    /// (Admin, Minter, Burner, Recall, Whitelist) to the `initialAdmin`.
    /// @param name The name of the token collection.
    /// @param symbol The symbol of the token collection.
    /// @param initialAdmin The address to receive initial administrative and operational roles. Must not be the zero address.
    constructor(string memory name, string memory symbol, address initialAdmin) ERC721(name, symbol) {
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
    function changeWhitelist(address account, bool status) external virtual onlyRole(WHITELIST_ROLE) {
        require(account != address(0), NotZeroAddress());
        isWhitelisted[account] = status;
        emit Whitelisted(account, status);
    }

    /// @notice Takes a specific token from one address and transfers it to another, bypassing standard transfer checks.
    /// @dev Implements the {IuRWA-recall} function for ERC-721. Requires the caller to have the `RECALL_ROLE`.
    /// Requires `to` not be the zero address.
    /// Directly updates ownership using the parent ERC721 `_update` function, bypassing this contract's override.
    /// Verifies that `from` was the actual owner before the update.
    /// Performs an ERC721 receiver check on `to` if it is a contract.
    /// Emits both a {Recalled} event and a standard {Transfer} event (via `super._update`).
    /// @param from The address from which `tokenId` is taken. Must be the current owner.
    /// @param to The address that receives `tokenId`. Must not be the zero address.
    /// @param tokenId The specific token identifier to recall. Must exist.
    function recall(address from, address to, uint256, uint256 tokenId) public virtual override onlyRole(RECALL_ROLE) {
        require(to != address(0), ERC721InvalidReceiver(address(0)));
        address previousOwner = super._update(to, tokenId, address(0)); // Skip _update override
        require(previousOwner != address(0), ERC721NonexistentToken(tokenId));
        require(previousOwner == from, ERC721IncorrectOwner(from, tokenId, previousOwner));
        
        ERC721Utils.checkOnERC721Received(_msgSender(), from, to, tokenId, "");
        emit Recalled(from, to, 1,  tokenId);
    }

    /// @notice Checks if a specific user is allowed to interact with the token based on the whitelist.
    /// @dev Implements the {IuRWA-isUserAllowed} function. Returns the status from the {isWhitelisted} mapping.
    /// Does not revert.
    /// @param user The address to check.
    /// @return allowed True if the user is whitelisted, false otherwise.
    function isUserAllowed(address user) public view virtual override returns (bool allowed) {
        return isWhitelisted[user];
    }

    /// @notice Checks if a transfer of a specific token is currently possible according to token rules.
    /// @dev Implements the {IuRWA-isTransferAllowed} function for ERC-721. Checks if `from` is the owner
    /// of `tokenId` and if both `from` and `to` are allowed users according to {isUserAllowed}.
    /// Uses internal `_ownerOf` to avoid reverting for non-existent tokens.
    /// Does not revert.
    /// @param from The address sending the token. Must be the owner.
    /// @param to The address receiving the token.
    /// @param tokenId The specific token identifier being transferred.
    /// @return allowed True if the transfer is allowed, false otherwise.
    function isTransferAllowed(address from, address to, uint256, uint256 tokenId) public view virtual override returns (bool allowed) {
        if (_ownerOf(tokenId) != from || _ownerOf(tokenId) == address(0)) return false; // Use internal function to avoid reverting for non existing tokenIds
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;
        // if (!_isAuthorized(from, _msgSender(), tokenId)) return false; // This check only makes sense whenever the transfer is being performed by a third party
        // if (to == address(0)) return false; // There is no real need to do this check as long as the zero address is not set in the whitelist

        return true;
    }

    /// @notice Safely creates a new token with `tokenId` and assigns it to `to`.
    /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    /// Requires `to` to be allowed according to {isUserAllowed} (enforced by the `_update` hook).
    /// Performs an ERC721 receiver check on `to` if it is a contract.
    /// Emits a {Transfer} event with `from` set to the zero address.
    /// @param to The address that will receive the minted token.
    /// @param tokenId The specific token identifier to mint.
    function safeMint(address to, uint256 tokenId) external virtual onlyRole(MINTER_ROLE) {
        _safeMint(to, tokenId);
    }

    /// @notice Destroys the token with `tokenId`.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Requires the caller (`_msgSender()`) to be the owner or approved for `tokenId`.
    /// Requires the owner (`from`) to be allowed according to {isUserAllowed} (enforced by the `_update` hook).
    /// Emits a {Transfer} event with `to` set to the zero address.
    /// @param tokenId The specific token identifier to burn.
    function burn(uint256 tokenId) external virtual onlyRole(BURNER_ROLE) {
        address previousOwner = _update(address(0), tokenId, _msgSender());
        if (previousOwner == address(0)) {
            revert ERC721NonexistentToken(tokenId);
        }
    }

    /// @notice Hook that is called before any token transfer, including minting and burning.
    /// @dev Overrides the ERC721 `_update` hook. Enforces transfer restrictions based on
    /// {isTransferAllowed} for regular transfers and {isUserAllowed} for minting and burning.
    /// Reverts with {TransferNotAllowed} or {UserNotAllowed} if checks fail.
    /// @param auth The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param value The amount being transferred.
    function _update(address to, uint256 value, address auth) internal virtual override returns(address) {
        address from = _ownerOf(value);

        if (auth != address(0)) {
            _checkAuthorized(from, auth, value);
        }

        if (from != address(0) && to != address(0)) { // Transfer
            require(isTransferAllowed(from, to, 1, value), TransferNotAllowed(from, to, 1, value));
        } else if (from == address(0)) { // Mint
            require(isUserAllowed(to), UserNotAllowed(to));
        } else { // Burn --> do we need to check is from isUserAllowed ?
            require(isUserAllowed(from), UserNotAllowed(from));
        }

        return super._update(to, value, auth);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IuRWA} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC721, IERC165) returns (bool) {
        return interfaceId == type(IuRWA).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}