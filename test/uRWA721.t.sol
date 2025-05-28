// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {uRWA721} from "../contracts/uRWA721.sol";
import {IERC7943} from "../contracts/interfaces/IERC7943.sol";
import {MockERC721Receiver} from "../contracts/mocks/MockERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IAccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol";

contract uRWA721Test is Test {
    uRWA721 public token;
    MockERC721Receiver public receiverContract;

    // Roles
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");
    bytes32 public constant ADMIN_ROLE = 0x00;

    // Users
    address public admin = address(1);
    address public user1 = address(2);
    address public user2 = address(3);
    address public minter = address(4);
    address public burner = address(5);
    address public enforcer = address(6);
    address public whitelister = address(7);
    address public nonWhitelistedUser = address(8);
    address public otherUser = address(9);

    // Token IDs
    uint256 public constant TOKEN_ID_1 = 1;
    uint256 public constant TOKEN_ID_2 = 2;
    uint256 public constant NON_EXISTENT_TOKEN_ID = 99;

    function setUp() public {
        vm.startPrank(admin);
        token = new uRWA721("uRWA NFT", "uNFT", admin);

        // Grant roles
        token.grantRole(MINTER_ROLE, minter);
        token.grantRole(BURNER_ROLE, burner);
        token.grantRole(ENFORCER_ROLE, enforcer);
        token.grantRole(WHITELIST_ROLE, whitelister);

        // Whitelist initial users
        token.changeWhitelist(admin, true);
        token.changeWhitelist(user1, true);
        token.changeWhitelist(user2, true);
        token.changeWhitelist(minter, true);
        token.changeWhitelist(burner, true);
        token.changeWhitelist(enforcer, true);
        token.changeWhitelist(whitelister, true);
        vm.stopPrank();

        // Deploy mock receiver
        receiverContract = new MockERC721Receiver();
        vm.prank(admin);
        token.changeWhitelist(address(receiverContract), true);

        // Mint initial token for tests
        vm.prank(minter);
        token.safeMint(user1, TOKEN_ID_1);
    }

    // --- Constructor Tests ---

    function test_Constructor_SetsNameAndSymbol() public view {
        assertEq(token.name(), "uRWA NFT");
        assertEq(token.symbol(), "uNFT");
    }

    function test_Constructor_GrantsInitialRoles() public view {
        assertTrue(token.hasRole(ADMIN_ROLE, admin));
        assertTrue(token.hasRole(MINTER_ROLE, admin));
        assertTrue(token.hasRole(BURNER_ROLE, admin));
        assertTrue(token.hasRole(ENFORCER_ROLE, admin));
        assertTrue(token.hasRole(WHITELIST_ROLE, admin));
    }

    function test_Revert_Constructor_ZeroAdminAddress() public {
        vm.expectRevert(uRWA721.NotZeroAddress.selector);
        new uRWA721("Fail", "FAIL", address(0));
    }

    // --- Whitelist Tests ---

    function test_Whitelist_ChangeStatus() public {
        assertFalse(token.isUserAllowed(otherUser));
        vm.prank(whitelister);
        vm.expectEmit(true, false, false, true);
        emit uRWA721.Whitelisted(otherUser, true);
        token.changeWhitelist(otherUser, true);
        assertTrue(token.isUserAllowed(otherUser));

        vm.prank(whitelister);
        vm.expectEmit(true, false, false, true);
        emit uRWA721.Whitelisted(otherUser, false);
        token.changeWhitelist(otherUser, false);
        assertFalse(token.isUserAllowed(otherUser));
    }

    function test_Revert_Whitelist_ChangeStatus_NotWhitelister() public {
        vm.prank(otherUser); // Not a whitelister
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, otherUser, WHITELIST_ROLE));
        token.changeWhitelist(nonWhitelistedUser, true);
    }

    function test_Revert_Whitelist_ChangeStatus_ZeroAddress() public {
        vm.prank(whitelister);
        vm.expectRevert(uRWA721.NotZeroAddress.selector);
        token.changeWhitelist(address(0), true);
    }

    function test_Whitelist_IsUserAllowed() public view {
        assertTrue(token.isUserAllowed(user1));
        assertFalse(token.isUserAllowed(nonWhitelistedUser));
    }

    // --- Minting Tests ---

    function test_Mint_Success() public {
        vm.prank(minter);
        vm.expectEmit(true, true, true, true);
        emit IERC721.Transfer(address(0), user2, TOKEN_ID_2);
        token.safeMint(user2, TOKEN_ID_2);
        assertEq(token.ownerOf(TOKEN_ID_2), user2);
    }

    function test_Revert_Mint_NotMinter() public {
        vm.prank(user1); // Not a minter
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, MINTER_ROLE));
        token.safeMint(user2, TOKEN_ID_2);
    }

    function test_Revert_Mint_ToNonWhitelisted() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, nonWhitelistedUser));
        token.safeMint(nonWhitelistedUser, TOKEN_ID_2);
    }

    function test_Revert_Mint_ExistingTokenId() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidSender.selector,address(0)));
        token.safeMint(user2, TOKEN_ID_1); // Already minted in setUp
    }

    function test_Revert_Mint_ToZeroAddress() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector,address(0)));
        token.safeMint(address(0), TOKEN_ID_2);
    }

    function test_Mint_ToContractReceiver() public {
        vm.prank(minter);
        token.safeMint(address(receiverContract), TOKEN_ID_2);
        assertEq(token.ownerOf(TOKEN_ID_2), address(receiverContract));
    }

    function test_Revert_Mint_ToContractThatRejects() public {
        receiverContract.setShouldReject(true);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector,address(receiverContract)));
        token.safeMint(address(receiverContract), TOKEN_ID_2);
    }

    // --- Burning Tests ---

    function test_Burn_Success_ByOwnerBurner() public {
        // Give burner role to user1 (owner)
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);

        vm.prank(user1); // Owner is now also burner
        vm.expectEmit(true, true, true, true);
        emit IERC721.Transfer(user1, address(0), TOKEN_ID_1);
        token.burn(TOKEN_ID_1);
        assertEq(token.balanceOf(user1), 0);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, TOKEN_ID_1));
        token.ownerOf(TOKEN_ID_1);
    }

     function test_Burn_Success_ByApprovedBurner() public {
        vm.prank(user1); // Owner approves burner
        token.approve(burner, TOKEN_ID_1);

        vm.prank(burner); // Burner (approved) burns the token
        vm.expectEmit(true, true, true, true);
        emit IERC721.Transfer(user1, address(0), TOKEN_ID_1);
        token.burn(TOKEN_ID_1);
        assertEq(token.balanceOf(user1), 0);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, TOKEN_ID_1));
        token.ownerOf(TOKEN_ID_1);
    }

    function test_Revert_Burn_NotBurnerRole() public {
        vm.prank(user1); // Owner does not have burner role
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, BURNER_ROLE));
        token.burn(TOKEN_ID_1);
    }

    function test_Revert_Burn_BurnerNotOwnerOrApproved() public {
        vm.startPrank(burner); // Burner is not owner or approved
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector, burner, TOKEN_ID_1));
        token.burn(TOKEN_ID_1);
        vm.stopPrank();
    }

    function test_Revert_Burn_OwnerNotWhitelisted() public {
        // Remove owner from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);

        // Give burner role to user1 (owner)
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);

        vm.prank(user1); // Owner (not whitelisted) tries to burn
        token.burn(TOKEN_ID_1);
    }

    function test_Revert_Burn_NonExistentToken() public {
        vm.prank(burner);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, NON_EXISTENT_TOKEN_ID));
        token.burn(NON_EXISTENT_TOKEN_ID);
    }

    // --- Transfer Tests ---

    function test_Transfer_Success_WhitelistedToWhitelisted() public {
        vm.prank(user1); // Owner
        vm.expectEmit(true, true, true, true);
        emit IERC721.Transfer(user1, user2, TOKEN_ID_1);
        token.transferFrom(user1, user2, TOKEN_ID_1);
        assertEq(token.ownerOf(TOKEN_ID_1), user2);
    }

    function test_Transfer_Success_ByApprovedWhitelisted() public {
        vm.prank(user1); // Owner approves otherUser
        token.approve(otherUser, TOKEN_ID_1);
        vm.prank(admin); // Whitelist otherUser
        token.changeWhitelist(otherUser, true);

        vm.prank(otherUser); // Approved user transfers
        vm.expectEmit(true, true, true, true);
        emit IERC721.Transfer(user1, user2, TOKEN_ID_1);
        token.transferFrom(user1, user2, TOKEN_ID_1);
        assertEq(token.ownerOf(TOKEN_ID_1), user2);
    }

    function test_Revert_Transfer_FromNotWhitelisted() public {
        // Remove user1 from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, 1));
        token.transferFrom(user1, user2, TOKEN_ID_1);
    }

    function test_Revert_Transfer_ToNotWhitelisted() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, nonWhitelistedUser, TOKEN_ID_1, 1));
        token.transferFrom(user1, nonWhitelistedUser, TOKEN_ID_1);
    }

     function test_Revert_Transfer_NotOwnerOrApproved() public {
        vm.prank(user2); // Not owner or approved
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector,user2, TOKEN_ID_1));
        token.transferFrom(user1, user2, TOKEN_ID_1);
    }

    function test_Revert_Transfer_FromIncorrectOwner() public {
        vm.prank(user1); // user1 approves user2 for TOKEN_ID_1
        token.approve(user2, TOKEN_ID_1);

        vm.prank(user2); // user2 tries to transfer from admin (incorrect owner)
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721IncorrectOwner.selector,admin, TOKEN_ID_1, user1));
        token.transferFrom(admin, user2, TOKEN_ID_1);
    }

    function test_Revert_Transfer_NonExistentToken() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, NON_EXISTENT_TOKEN_ID));
        token.transferFrom(user1, user2, NON_EXISTENT_TOKEN_ID);
    }

    function test_Revert_Transfer_ToZeroAddress() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector,address(0)));
        token.transferFrom(user1, address(0), TOKEN_ID_1);
    }

    // --- ForceTransfer Tests ---

    function test_ForceTransfer_Success_WhitelistedToWhitelisted() public {
        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true); // Transfer event from super._update
        emit IERC721.Transfer(user1, user2, TOKEN_ID_1);
        vm.expectEmit(true, true, true, true); // ForcedTransfer event
        emit IERC7943.ForcedTransfer(user1, user2, TOKEN_ID_1, 1);
        token.forceTransfer(user1, user2, TOKEN_ID_1, 1);
        assertEq(token.ownerOf(TOKEN_ID_1), user2);
    }

    function test_ForceTransfer_Success_FromNonWhitelistedToWhitelisted() public {
        // Remove user1 from whitelist
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);
        assertFalse(token.isUserAllowed(user1));

        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true); // Transfer event
        emit IERC721.Transfer(user1, user2, TOKEN_ID_1);
        vm.expectEmit(true, true, true, true); // ForcedTransfer event
        emit IERC7943.ForcedTransfer(user1, user2, TOKEN_ID_1, 1);
        token.forceTransfer(user1, user2, TOKEN_ID_1, 1); // Succeeds as 'from' whitelist status is not checked
        assertEq(token.ownerOf(TOKEN_ID_1), user2);
    }

    function test_Revert_ForceTransfer_ToNonWhitelisted() public {
        // ForceTransfer to non-whitelisted user
        assertFalse(token.isUserAllowed(nonWhitelistedUser));
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, nonWhitelistedUser));
        token.forceTransfer(user1, nonWhitelistedUser, TOKEN_ID_1, 1);
    }

    function test_Revert_ForceTransfer_NotForceTransferrer() public {
        vm.prank(user1); // Not enforcer
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ENFORCER_ROLE));
        token.forceTransfer(user1, user2, TOKEN_ID_1, 1);
    }

    function test_Revert_ForceTransfer_NonExistentToken() public {
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, NON_EXISTENT_TOKEN_ID));
        token.forceTransfer(user1, user2, NON_EXISTENT_TOKEN_ID, 1);
    }

    function test_Revert_ForceTransfer_FromIncorrectOwner() public {
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721IncorrectOwner.selector,user2,TOKEN_ID_1,user1));
        token.forceTransfer(user2, admin, TOKEN_ID_1, 1); // user2 is not the owner
    }

    function test_Revert_ForceTransfer_ToZeroAddress() public {
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector,address(0)));
        token.forceTransfer(user1, address(0), TOKEN_ID_1, 1);
    }

     // --- Freeze/Unfreeze Tests ---

    function test_Freeze_Success() public {
        vm.prank(enforcer); // ENFORCER_ROLE
        vm.expectEmit(true, true, true, false);
        emit IERC7943.Frozen(user1, TOKEN_ID_1, 1);
        token.setFrozen(user1, TOKEN_ID_1, 1);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 1, "Token should be frozen");
    }

    function test_Revert_Freeze_NotEnforcer() public {
        vm.prank(user1); // Not ENFORCER_ROLE
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ENFORCER_ROLE));
        token.setFrozen(user1, TOKEN_ID_1, 1);
    }

    function test_Revert_Freeze_NotOwner() public {
        vm.prank(enforcer); // ENFORCER_ROLE
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidOwner.selector, user2));
        token.setFrozen(user2, TOKEN_ID_1, 1); // user2 is not owner of TOKEN_ID_1
    }

    function test_Unfreeze_Success() public {
        // First, freeze the token
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 1, "Token should be frozen initially");

        // Then, unfreeze
        vm.prank(enforcer); // ENFORCER_ROLE
        vm.expectEmit(true, true, true, false);
        emit IERC7943.Frozen(user1, TOKEN_ID_1, 0);
        token.setFrozen(user1, TOKEN_ID_1, 0);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 0, "Token should be unfrozen");
    }

    function test_Revert_Unfreeze_NotEnforcer() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1); // Freeze first

        vm.prank(user1); // Not ENFORCER_ROLE
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ENFORCER_ROLE));
        token.setFrozen(user1, TOKEN_ID_1, 0);
    }

    function test_Revert_Unfreeze_NotOwner() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1); // Freeze first for user1

        vm.prank(enforcer); // ENFORCER_ROLE
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidOwner.selector, user2));
        token.setFrozen(user2, TOKEN_ID_1, 0);
    }

    function test_FreezeStatus_Correctness() public {
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 0, "Initially token should not be frozen");

        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 1, "Token should be frozen");

        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 0);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 0, "Token should be unfrozen");
    }

    function test_Revert_Transfer_WhenFrozen() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1); // Freeze TOKEN_ID_1 for user1

        vm.prank(user1); // Owner attempts transfer
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, 1));
        token.transferFrom(user1, user2, TOKEN_ID_1);
    }

    function test_Revert_Burn_WhenFrozen() public {
        // Grant burner role to user1
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);

        // Freeze the token
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1);

        vm.prank(user1); // Owner (and burner) attempts to burn
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAvailableAmount.selector, user1, TOKEN_ID_1, 1, 0));
        token.burn(TOKEN_ID_1);
    }

    function test_ForceTransfer_UnfreezesToken() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 1);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 1, "Token should be frozen before force transfer");

        vm.prank(enforcer);
        token.forceTransfer(user1, user2, TOKEN_ID_1, 1);

        assertEq(token.ownerOf(TOKEN_ID_1), user2, "Owner should be user2 after force transfer");
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 0, "Token should be unfrozen for original owner after force transfer");
        assertEq(token.getFrozen(user2, TOKEN_ID_1), 0, "Token should not be frozen for new owner");
    }

    // --- Interface Support Tests ---

    function test_Interface_SupportsIERC7943() public view {
        assertTrue(token.supportsInterface(type(IERC7943).interfaceId));
    }

    function test_Interface_SupportsIERC721() public view {
        assertTrue(token.supportsInterface(type(IERC721).interfaceId));
    }

     function test_Interface_SupportsIERC165() public view {
        assertTrue(token.supportsInterface(type(IERC165).interfaceId));
    }

    function test_Interface_SupportsAccessControl() public view {
        assertTrue(token.supportsInterface(type(IAccessControlEnumerable).interfaceId));
    }

    function test_Interface_DoesNotSupportRandom() public view {
        assertFalse(token.supportsInterface(bytes4(0xdeadbeef)));
    }

     // --- Access Control Tests ---

    function test_AccessControl_GrantRevokeRole() public {
        assertFalse(token.hasRole(MINTER_ROLE, user1));
        vm.prank(admin);
        token.grantRole(MINTER_ROLE, user1);
        assertTrue(token.hasRole(MINTER_ROLE, user1));
        vm.prank(admin);
        token.revokeRole(MINTER_ROLE, user1);
        assertFalse(token.hasRole(MINTER_ROLE, user1));
    }

    function test_Revert_AccessControl_GrantRole_NotAdmin() public {
        vm.prank(user1); // Not admin
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ADMIN_ROLE));
        token.grantRole(MINTER_ROLE, user2);
    }

    // --- isTransferAllowed Tests ---

    function test_IsTransferAllowed_Success() public view {
        assertTrue(token.isTransferAllowed(user1, user2, TOKEN_ID_1, 1));
    }

    function test_IsTransferAllowed_Fail_FromNotOwner() public view {
        assertFalse(token.isTransferAllowed(user2, user1, TOKEN_ID_1, 1)); // user2 is not owner
    }

    function test_IsTransferAllowed_Fail_NonExistentToken() public view {
        assertFalse(token.isTransferAllowed(user1, user2, NON_EXISTENT_TOKEN_ID, 1));
    }

    function test_IsTransferAllowed_Fail_FromNotWhitelisted() public {
        vm.prank(whitelister);
        token.changeWhitelist(user1, false); // Remove owner from whitelist
        assertFalse(token.isTransferAllowed(user1, user2, TOKEN_ID_1, 1));
    }

    function test_IsTransferAllowed_Fail_ToNotWhitelisted() public view {
        assertFalse(token.isTransferAllowed(user1, nonWhitelistedUser, TOKEN_ID_1, 1));
    }
}