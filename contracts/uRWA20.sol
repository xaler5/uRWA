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
        require(isUserAllowed(to), ERC7943NotAllowedUser(to));
        _mint(to, amount);
    }

    /// @notice Destroys `amount` tokens for a given `from` address.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Emits a {Transfer} event with `to` set to the zero address.
    /// It unfreezes tokens if required to satisfy `amount` burn.
    /// @param from The address from which tokens are burned.
    /// @param amount The amount of tokens to burn.
    function burn(address from, uint256 amount) external onlyRole(BURNER_ROLE) {
        // Unfreeze tokens if possible and required.
        uint256 unfrozenBalance = balanceOf(from) - _frozenTokens[from];
        if (amount > unfrozenBalance && balanceOf(from) >= amount) {
            _setFrozen(from, amount - unfrozenBalance);
        }
        _burn(from, amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`
    function setFrozen(address user, uint256, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(amount <= balanceOf(user), IERC20Errors.ERC20InsufficientBalance(user, balanceOf(user), amount));
        _setFrozen(user, amount);
    }

    /// @inheritdoc IERC7943
    /// @dev Can only be called by accounts holding the `ENFORCER_ROLE`.
    /// It unfreezes tokens if required to satisfy `amount` transfer.
    function forceTransfer(address from, address to, uint256, uint256 amount) public onlyRole(ENFORCER_ROLE) {
        require(isUserAllowed(to), ERC7943NotAllowedUser(to));
        // Unfreeze tokens if possible and required.
        uint256 unfrozenBalance = balanceOf(from) - _frozenTokens[from];
        if (amount > unfrozenBalance && balanceOf(from) >= amount) {
            _setFrozen(from, amount - unfrozenBalance);
        }
        super._transfer(from, to, amount);
        emit ForcedTransfer(from, to, 0, amount);
    }

    /// @inheritdoc IERC20
    /// @dev Enforces ERC-7943 transfer restrictions.
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        _validatePublicTransfer(_msgSender(), to, amount);
        return super.transfer(to, amount);
    }

    /// @inheritdoc IERC20
    /// @dev Enforces ERC-7943 transfer restrictions.
    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        _validatePublicTransfer(from, to, amount);
        return super.transferFrom(from, to, amount);
    }

    /// @notice Validates a public transfer according to the rules defined in ERC-7943.
    /// @dev Checks if both `from` and `to` are whitelisted, if the transfer is allowed,
    /// and if the `amount` does not exceed the available balance after accounting for frozen tokens.
    /// @param from The sender address.
    /// @param to The recipienta address.
    /// @param amount The amount of tokens to transfer.
    function _validatePublicTransfer(address from, address to, uint256 amount) internal view virtual {
        require(isUserAllowed(from), ERC7943NotAllowedUser(from));
        require(isUserAllowed(to), ERC7943NotAllowedUser(to));
        require(isTransferAllowed(from, to, 0, amount), ERC7943NotAllowedTransfer(from, to, 0, amount));
        uint256 balance  = balanceOf(from);
        uint256 unfrozen = balance - _frozenTokens[from];
        // `ERC20._update` will throw `ERC20InsufficientBalance` if `balance < amount`.
        require(unfrozen >= amount || balance < amount, ERC7943InsufficientUnfrozenBalance(from, 0, amount, unfrozen));
        // Zero address check is handled by `ERC20._transfer`.
    }

    function _setFrozen(address user, uint256 amount) internal virtual {
        _frozenTokens[user] = amount;
        emit Frozen(user, 0, amount);
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