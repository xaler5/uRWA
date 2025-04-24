// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IuRWA} from "./interfaces/IuRWA.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";

contract uRWA721 is Context, ERC721, AccessControlEnumerable, IuRWA {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant RECALL_ROLE = keccak256("RECALL_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    mapping(address user => bool whitelisted) public isWhitelisted;

    event Whitelisted(address indexed account, bool status);

    error NotZeroAddress();

    constructor(string memory name, string memory symbol, address initialAdmin) ERC721(name, symbol) {
        require(initialAdmin != address(0), NotZeroAddress());
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(RECALL_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);

    }

    function changeWhitelist(address account, bool status) external virtual onlyRole(WHITELIST_ROLE) {
        require(initialAdmin != address(0), NotZeroAddress());
        isWhitelisted[account] = status;
        emit Whitelisted(account, status);
    }

    // NOTE it might require target to be isUserAllowed(target)
    function recall(address from, address to, uint256 tokenId) external virtual override onlyRole(RECALL_ROLE) {
        require(to != address(0), ERC721InvalidReceiver(address(0)));
        address previousOwner = super._update(to, tokenId, address(0)); // Skip _update override
        require(previousOwner != address(0), ERC721NonexistentToken(tokenId));
        require(previousOwner == from, ERC721IncorrectOwner(from, tokenId, previousOwner));
        
        ERC721Utils.checkOnERC721Received(_msgSender(), from, to, tokenId, data);
        emit Recalled(from, to, tokenId);
    }

    function isUserAllowed(address user) public view virtual override returns (bool allowed) {
        return isWhitelisted[user];
    }

    function isTransferAllowed(address from, address to, uint256 tokenId) public view virtual override returns (bool allowed) {
        if (_ownerOf(tokenId) != from || _ownerOf(tokenId) == address(0)) return false; // Use internal function to avoid reverting for non existing tokenIds
        if (!isUserAllowed(from) || !isUserAllowed(to)) return false;
        // if (!_isAuthorized(from, _msgSender(), tokenId)) return false; // This check only makes sense whenever the transfer is being performed by a third party
        // if (to == address(0)) return false; // There is no real need to do this check as long as the zero address is not set in the whitelist

        return true;
    }

    function safeMint(address to, uint256 tokenId) external virtual onlyRole(MINTER_ROLE) {
        _safeMint(to, tokenId);
    }

    function burn(uint256 tokenId) external virtual onlyRole(BURNER_ROLE) {
        _burn(tokenId);
    }

    function _update(address from, address to, uint256 value) internal virtual override {
        if (from != address(0) && to != address(0)) { // Transfer
            require(isTransferAllowed(from, to, value), TransferNotAllowed(from, to, value));
        } else if (from == address(0)) { // Mint
            require(isUserAllowed(to), UserNotAllowed(to));
        } else { // Burn --> do we need to check is from isUserAllowed ?
            require(isUserAllowed(from), UserNotAllowed(from));
        }

        super._update(from, to, value);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC721, IERC165) returns (bool) {
        return interfaceId == type(IuRWA).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}