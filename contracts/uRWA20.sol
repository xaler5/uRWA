// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC7943} from "./interfaces/IERC7943.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @title uRWA-20 Token Contract
/// @notice An ERC-20 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-20 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers, and freezing. Managed via AccessControl.
contract uRWA20 is Context, ERC20, AccessControlEnumerable, IERC7943 {
    /// @notice Role identifiers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    /// @notice Mapping storing the whitelist status for each user address.
    /// @dev True indicates the user is whitelisted and allowed to interact, false otherwise.
    mapping(address user => bool whitelisted) public isWhitelisted;

    /// @notice Mapping storing the freezing status of assets for each user address.
    /// @dev It gives the amount of ERC-20 tokens frozen in `user` wallet.
    mapping(address user => uint256 amount) internal _frozenTokens;

    /// @notice Emitted when an account's whitelist status is changed.
    /// @param account The address whose status was changed.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    event Whitelisted(address indexed account, bool status);
 
    /// @notice Error reverted when an operation requires a non-zero address but address(0) was provided.
    error NotZeroAddress();

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-20 token with name and symbol, and grants all roles
    /// (Admin, Minter, Burner, Enforcer, Whitelist) to the `initialAdmin`.
    /// @param name The name of the token.
    /// @param symbol The symbol of the token.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    constructor(string memory name, string memory symbol, address initialAdmin) ERC20(name, symbol) {
        require(initialAdmin != address(0), NotZeroAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(ENFORCER_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
    }

    /// @inheritdoc IERC7943
    function isTransferAllowed(address from, address to, uint256, uint256 amount) public virtual view returns (bool allowed) {
        if (amount > balanceOf(from) - _frozenTokens[from]) return false;
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;

        return true;
    }

    /// @inheritdoc IERC7943
    function isUserAllowed(address user) public virtual view returns (bool allowed) {
        if (!isWhitelisted[user]) return false;
        
        return true;
    } 

    /// @inheritdoc IERC7943
    function getFrozen(address user, uint256) external view returns (uint256 amount) {
        amount = _frozenTokens[user];
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
    /// Emits a {Transfer} event with `to` set to the zero address.
    /// @param amount The amount of tokens to burn.
    function burn(uint256 amount) external onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`
    function setFrozen(address user, uint256, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(amount <= balanceOf(user), IERC20Errors.ERC20InsufficientBalance(user, balanceOf(user), amount));
        _frozenTokens[user] = amount;
        emit Frozen(user, 0, amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`.
    function forceTransfer(address from, address to, uint256, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(isUserAllowed(to), ERC7943NotAllowedUser(to));

        // Directly update balances, bypassing overridden _update
        super._update(from, to, amount);

        // If more than unfrozen amount has been transferred, update frozen amount
        if(_frozenTokens[from] > balanceOf(from)) {
            _frozenTokens[from] = balanceOf(from);
            emit Frozen(from, 0, _frozenTokens[from]);
        }

        emit ForcedTransfer(from, to, 0, amount);
    }

    /// @notice Hook that is called during any token transfer, including minting and burning.
    /// @dev Overrides the ERC-20 `_update` hook. Enforces transfer restrictions based on
    /// {isTransferAllowed} for regular transfers and {isUserAllowed} for minting and burning.
    /// Reverts with {ERC7943NotAllowedTransfer}, {ERC7943NotAllowedUser} or {ERC7943InsufficientUnfrozenBalance} if checks fail.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param amount The amount being transferred.
    function _update(address from, address to, uint256 amount) internal virtual override {
        if (from != address(0) && to != address(0)) { // Transfer
            require(isTransferAllowed(from, to, 0, amount), ERC7943NotAllowedTransfer(from, to, 0, amount)); // isTransferAllowed checks for frozen assets
        } else if (from == address(0)) { // Mint
            require(isUserAllowed(to), ERC7943NotAllowedUser(to));
        } else { // Burn - Can't burn more than unfrozen balance
            uint256 available = balanceOf(from) - _frozenTokens[from];
            require(amount <= available || amount < balanceOf(from), ERC7943InsufficientUnfrozenBalance(from, 0, amount, available));
        } 

        super._update(from, to, amount);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IERC-7943} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, IERC165) returns (bool) {
        return interfaceId == type(IERC7943).interfaceId ||
            interfaceId == type(IERC20).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}