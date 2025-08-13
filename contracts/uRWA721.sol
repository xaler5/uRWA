// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC7943} from "./interfaces/IERC7943.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721Utils} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Utils.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @title uRWA-721 Token Contract
/// @notice An ERC-721 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-721 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers, and freezing. Managed via AccessControl and represents unique assets.
contract uRWA721 is Context, ERC721, AccessControlEnumerable, IERC7943 {
    /// @notice Role identifiers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    /// @notice Mapping storing the whitelist status for each user address.
    /// @dev True indicates the user is whitelisted and allowed to interact, false otherwise.
    mapping(address user => bool whitelisted) public isWhitelisted;

    /// @notice Mapping storing the freezing status of assets for each user address.
    /// @dev It gives 1 (True) or 0 (False) on whether the `tokenId` is frozen for `user`.
    mapping(address user => mapping(uint256 tokenId => uint8 frozen)) internal _frozenTokens;

    /// @notice Emitted when an account's whitelist status is changed.
    /// @param account The address whose status was changed.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    event Whitelisted(address indexed account, bool status);

    /// @notice Error reverted when an operation requires a non-zero address but address(0) was provided.
    error NotZeroAddress(); 

    /// @notice Error reverted when an operation requires a 0/1 amount but something else was provided.
    error InvalidAmount(uint256 amount);

    /// @notice Error reverted when a transfer is not allowed due to restrictions in place.
    error UnauthorizedTransfer(address from, address to, uint256 tokenId, uint256 amount);

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-721 token with name and symbol, and grants all roles
    /// (Admin, Minter, Burner, Enforcer, Whitelist) to the `initialAdmin`.
    /// @param name The name of the token collection.
    /// @param symbol The symbol of the token collection.
    /// @param initialAdmin The address to receive initial administrative and operational roles. Must not be the zero address.
    constructor(string memory name, string memory symbol, address initialAdmin) ERC721(name, symbol) {
        require(initialAdmin != address(0), NotZeroAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(ENFORCER_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);

    }

    /// @inheritdoc IERC7943
    function isUserAllowed(address user) public view virtual override returns (bool allowed) {
        if (!isWhitelisted[user]) return false;
        
        return true;
    }

    /// @inheritdoc IERC7943
    function canTransfer(address from, address to, uint256 tokenId, uint256) public view virtual override returns (bool allowed) {
        address owner = _ownerOf(tokenId);
        if (owner != from || owner == address(0)) return false; // Use internal function to avoid reverting for non existing tokenIds
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;
        if (_frozenTokens[from][tokenId] > 0) return false; // The token is frozen for the user

        return true;
    }

    /// @inheritdoc IERC7943
    function getFrozenTokens(address user, uint256 tokenId) external view returns (uint256 amount) {
        amount = _frozenTokens[user][tokenId];
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
    /// Emits a {Transfer} event with `to` set to the zero address.
    /// @param tokenId The specific token identifier to burn. 
    function burn(uint256 tokenId) external virtual onlyRole(BURNER_ROLE) {
        address previousOwner = _update(address(0), tokenId, _msgSender()); 
        if (previousOwner == address(0)) revert ERC721NonexistentToken(tokenId);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`
    function setFrozenTokens(address user, uint256 tokenId, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(user == ownerOf(tokenId), IERC721Errors.ERC721InvalidOwner(user));
        require(amount == 0 || amount == 1, InvalidAmount(amount));
        
        _frozenTokens[user][tokenId] = uint8(amount);

        emit Frozen(user, tokenId, amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`.
    function forcedTransfer(address from, address to, uint256 tokenId, uint256) public virtual override onlyRole(ENFORCER_ROLE) {
        require(to != address(0), ERC721InvalidReceiver(address(0)));
        require(isUserAllowed(to), ERC7943NotAllowedUser(to));

        _excessFrozenUpdate(from , tokenId);

        super._update(to, tokenId, address(0)); // Skip _update override
        ERC721Utils.checkOnERC721Received(_msgSender(), from, to, tokenId, "");
        
        emit ForcedTransfer(from, to, tokenId, 1);
    }

    function _excessFrozenUpdate(address from, uint256 tokenId) internal {
        _validateCorrectOwner(from, tokenId);
        if(_frozenTokens[from][tokenId] > 0) {
            _frozenTokens[from][tokenId] = 0; // Unfreeze the token if it was frozen
            emit Frozen(from, tokenId, 0);
        }
    }

    function _validateCorrectOwner(address claimant, uint256 tokenId) internal view {
        address currentOwner = ownerOf(tokenId);

        require(currentOwner == claimant, ERC721IncorrectOwner(claimant, tokenId, currentOwner));
    }

    /// @notice Hook that is called during any token transfer, including minting and burning.
    /// @dev Overrides the ERC-721 `_update` hook. Enforces transfer restrictions based on
    /// {canTransfer} for regular transfers and {isUserAllowed} for minting.
    /// Reverts with {ERC7943NotAllowedUser}. {ERC7943InsufficientUnfrozenBalance}, {UnauthorizedTransfer} or any of the base
    /// token errors if checks fail.
    /// @param to The address receiving tokens (zero address for burning).
    /// @param tokenId The if of the token being transferred.
    /// @param auth The address sending tokens (zero address for minting).
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns(address) {
        address from = _ownerOf(tokenId);

        if (auth != address(0)) {
            _checkAuthorized(from, auth, tokenId);
        }

        if (from != address(0) && to != address(0)) { // Transfer
            _validateCorrectOwner(from, tokenId);
            require(_frozenTokens[from][tokenId] == 0, ERC7943InsufficientUnfrozenBalance(from, tokenId, 1, 0));
            require(canTransfer(from, to, tokenId, 1), UnauthorizedTransfer(from, to, tokenId, 1));
        } else if (from == address(0)) { // Mint
            require(isUserAllowed(to), ERC7943NotAllowedUser(to));
        } else {
            _excessFrozenUpdate(from, tokenId);
        } 

        return super._update(to, tokenId, auth);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IERC-7943} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC721, IERC165) returns (bool) {
        return interfaceId == type(IERC7943).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}
