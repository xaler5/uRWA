// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {uRWA1155} from "../contracts/uRWA1155.sol";
import {IERC7943} from "../contracts/interfaces/IERC7943.sol";
import {MockERC1155Receiver} from "../contracts/mocks/MockERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IAccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/IAccessControlEnumerable.sol";

contract uRWA1155Test is Test {
    uRWA1155 public token;
    MockERC1155Receiver public receiverContract;
    string public constant TOKEN_URI = "ipfs://test.uri/{id}.json";

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

    // Token IDs and Amounts
    uint256 public constant TOKEN_ID_1 = 1;
    uint256 public constant TOKEN_ID_2 = 2;
    uint256 public constant NON_EXISTENT_TOKEN_ID = 99;
    uint256 public constant MINT_AMOUNT = 100;
    uint256 public constant TRANSFER_AMOUNT = 50;
    uint256 public constant BURN_AMOUNT = 20;
    uint256 public constant FORCE_TRANSFER_AMOUNT = 30;
    uint256 public constant FREEZE_AMOUNT = 40;


    function setUp() public {
        vm.startPrank(admin);
        token = new uRWA1155(TOKEN_URI, admin);

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
        receiverContract = new MockERC1155Receiver();
        vm.prank(admin);
        token.changeWhitelist(address(receiverContract), true);

        // Mint initial tokens for tests
        vm.prank(minter);
        token.mint(user1, TOKEN_ID_1, MINT_AMOUNT);
        vm.prank(minter);
        token.mint(user1, TOKEN_ID_2, MINT_AMOUNT);
    }

    // --- Constructor Tests ---

    function test_Constructor_SetsURI() public view {
        assertEq(token.uri(TOKEN_ID_1), TOKEN_URI);
    }

    function test_Constructor_GrantsInitialRoles() public view {
        assertTrue(token.hasRole(ADMIN_ROLE, admin));
        assertTrue(token.hasRole(MINTER_ROLE, admin));
        assertTrue(token.hasRole(BURNER_ROLE, admin));
        assertTrue(token.hasRole(ENFORCER_ROLE, admin));
        assertTrue(token.hasRole(WHITELIST_ROLE, admin));
    }

    function test_Revert_Constructor_ZeroAdminAddress() public {
        vm.expectRevert(uRWA1155.NotZeroAddress.selector);
        new uRWA1155(TOKEN_URI, address(0));
    }

    // --- Whitelist Tests ---

    function test_Whitelist_ChangeStatus() public {
        assertFalse(token.isUserAllowed(otherUser));
        vm.prank(whitelister);
        vm.expectEmit(true, false, false, true);
        emit uRWA1155.Whitelisted(otherUser, true);
        token.changeWhitelist(otherUser, true);
        assertTrue(token.isUserAllowed(otherUser));

        vm.prank(whitelister);
        vm.expectEmit(true, false, false, true);
        emit uRWA1155.Whitelisted(otherUser, false);
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
        vm.expectRevert(uRWA1155.NotZeroAddress.selector);
        token.changeWhitelist(address(0), true);
    }

    // --- Minting Tests ---

    function test_Mint_Success() public {
        vm.prank(minter);
        vm.expectEmit(true, true, true, true);
        emit IERC1155.TransferSingle(minter, address(0), user2, TOKEN_ID_2, MINT_AMOUNT);
        token.mint(user2, TOKEN_ID_2, MINT_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_2), MINT_AMOUNT);
    }

    function test_Revert_Mint_NotMinter() public {
        vm.prank(user1); // Not a minter
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, MINTER_ROLE));
        token.mint(user2, TOKEN_ID_2, MINT_AMOUNT);
    }

    function test_Revert_Mint_ToNonWhitelisted() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, nonWhitelistedUser));
        token.mint(nonWhitelistedUser, TOKEN_ID_2, MINT_AMOUNT);
    }

    function test_Revert_Mint_ToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(0)));
        vm.prank(minter);
        token.mint(address(0), TOKEN_ID_2, MINT_AMOUNT);
    }

    function test_Mint_ToContractReceiver() public {
        vm.prank(minter);
        token.mint(address(receiverContract), TOKEN_ID_2, MINT_AMOUNT);
        assertEq(token.balanceOf(address(receiverContract), TOKEN_ID_2), MINT_AMOUNT);
    }

    function test_Revert_Mint_ToContractThatRejects() public {
        receiverContract.setShouldReject(true);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(receiverContract)));
        token.mint(address(receiverContract), TOKEN_ID_2, MINT_AMOUNT);
    }

    // --- Burning Tests ---

    function test_Burn_Success() public {
        // Grant burner role to user1 for this test
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);

        uint256 initialBalance = token.balanceOf(user1, TOKEN_ID_1);
        vm.prank(user1); // User1 (owner and burner) burns tokens
        vm.expectEmit(true, true, true, true);
        emit IERC1155.TransferSingle(user1, user1, address(0), TOKEN_ID_1, BURN_AMOUNT);
        token.burn(TOKEN_ID_1, BURN_AMOUNT);
        assertEq(token.balanceOf(user1, TOKEN_ID_1), initialBalance - BURN_AMOUNT);
    }

    function test_Revert_Burn_NotBurnerRole() public {
        vm.prank(user1); // Owner does not have burner role by default
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, BURNER_ROLE));
        token.burn(TOKEN_ID_1, BURN_AMOUNT);
    }

    function test_Revert_Burn_InsufficientBalance() public {
        uint256 available = token.balanceOf(user1, TOKEN_ID_1) - token.getFrozen(user1, TOKEN_ID_1);
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);
        vm.prank(user1);
        uint256 burnAmount = available + 1; // More than available
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943InsufficientUnfrozenBalance.selector, user1, TOKEN_ID_1, burnAmount, available));
        token.burn(TOKEN_ID_1, burnAmount);
    }

    // TODO: fix and un-skip.
    function test_Revert_Burn_FrozenTokens() internal {
        vm.prank(admin);
        token.grantRole(BURNER_ROLE, user1);
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT); // Freeze some tokens
        uint256 available = token.balanceOf(user1, TOKEN_ID_1) - token.getFrozen(user1, TOKEN_ID_1);

        vm.prank(user1);
        // Attempt to burn more than available (balance - frozen)
        uint256 availableToBurn = MINT_AMOUNT - FREEZE_AMOUNT;
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943InsufficientUnfrozenBalance.selector, user1, TOKEN_ID_1, availableToBurn + 1, available));
        token.burn(TOKEN_ID_1, availableToBurn + 1);
    }


    // --- Transfer Tests (safeTransferFrom) ---

    function test_Transfer_Success_WhitelistedToWhitelisted() public {
        uint256 user1InitialBalance = token.balanceOf(user1, TOKEN_ID_1);
        uint256 user2InitialBalance = token.balanceOf(user2, TOKEN_ID_1);
        vm.prank(user1); // Owner
        vm.expectEmit(true, true, true, true);
        emit IERC1155.TransferSingle(user1, user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT);
        token.safeTransferFrom(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT, "");
        assertEq(token.balanceOf(user1, TOKEN_ID_1), user1InitialBalance - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_1), user2InitialBalance + TRANSFER_AMOUNT);
    }

    function test_Transfer_Success_ByApprovedWhitelisted() public {
        vm.prank(user1); // Owner approves otherUser
        token.setApprovalForAll(otherUser, true);
        vm.prank(admin); // Whitelist otherUser
        token.changeWhitelist(otherUser, true);

        vm.prank(otherUser); // Approved user transfers
        token.safeTransferFrom(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT, "");
        assertEq(token.balanceOf(user1, TOKEN_ID_1), MINT_AMOUNT - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_1), TRANSFER_AMOUNT);
    }

    function test_Revert_Transfer_FromNotWhitelisted() public {
        vm.prank(whitelister);
        token.changeWhitelist(user1, false); // Remove user1 from whitelist

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT));
        token.safeTransferFrom(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT, "");
    }

    function test_Revert_Transfer_ToNotWhitelisted() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, nonWhitelistedUser, TOKEN_ID_1, TRANSFER_AMOUNT));
        token.safeTransferFrom(user1, nonWhitelistedUser, TOKEN_ID_1, TRANSFER_AMOUNT, "");
    }

    function test_Revert_Transfer_NotApproved() public {
        vm.prank(user2); // Not approved
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155MissingApprovalForAll.selector, user2, user1));
        token.safeTransferFrom(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT, "");
    }

    function test_Revert_Transfer_InsufficientBalance() public {
        vm.prank(user1);
        uint256 transferAmount = MINT_AMOUNT + 1;
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, transferAmount));
        token.safeTransferFrom(user1, user2, TOKEN_ID_1, transferAmount, "");
    }
    
    function test_Revert_Transfer_ToZeroAddress() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(0)));
        token.safeTransferFrom(user1, address(0), TOKEN_ID_1, TRANSFER_AMOUNT, "");
    }

    function test_Revert_Transfer_WhenFrozen() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT);

        vm.prank(user1);
        // Attempt to transfer more than available (MINT_AMOUNT - FREEZE_AMOUNT)
        uint256 availableToTransfer = MINT_AMOUNT - FREEZE_AMOUNT;
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, availableToTransfer + 1));
        token.safeTransferFrom(user1, user2, TOKEN_ID_1, availableToTransfer + 1, "");
    }

    function test_Revert_SafeTransfer_ToContractThatRejects() public {
        receiverContract.setShouldReject(true);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(receiverContract)));
        vm.prank(user1);
        token.safeTransferFrom(user1, address(receiverContract), TOKEN_ID_1, TRANSFER_AMOUNT, "");
    }

    // --- ForceTransfer Tests ---

    function test_ForceTransfer_Success_WhitelistedToWhitelisted() public {
        uint256 user1InitialBalance = token.balanceOf(user1, TOKEN_ID_1);
        uint256 user2InitialBalance = token.balanceOf(user2, TOKEN_ID_1);

        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true); // TransferSingle event
        emit IERC1155.TransferSingle(enforcer, user1, user2, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
        vm.expectEmit(true, true, true, true); // ForcedTransfer event
        emit IERC7943.ForcedTransfer(user1, user2, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);

        token.forceTransfer(user1, user2, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user1, TOKEN_ID_1), user1InitialBalance - FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_1), user2InitialBalance + FORCE_TRANSFER_AMOUNT);
    }

    function test_ForceTransfer_Success_FromNonWhitelistedToWhitelisted() public {
        vm.prank(whitelister);
        token.changeWhitelist(user1, false); // Remove user1 from whitelist

        vm.prank(enforcer);
        token.forceTransfer(user1, user2, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user1, TOKEN_ID_1), MINT_AMOUNT - FORCE_TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_1), FORCE_TRANSFER_AMOUNT);
    }

    function test_Revert_ForceTransfer_ToNonWhitelisted() public {
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, nonWhitelistedUser));
        token.forceTransfer(user1, nonWhitelistedUser, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
    }

    function test_Revert_ForceTransfer_NotEnforcer() public {
        vm.prank(user1); // Not enforcer
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, ENFORCER_ROLE));
        token.forceTransfer(user1, user2, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
    }

    function test_Revert_ForceTransfer_InsufficientBalance() public {
        uint256 forceAmount = MINT_AMOUNT + 1;
        vm.prank(enforcer);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InsufficientBalance.selector, user1, MINT_AMOUNT, forceAmount, TOKEN_ID_1));
        token.forceTransfer(user1, user2, TOKEN_ID_1, forceAmount);
    }
    
    function test_Revert_ForceTransfer_ToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedUser.selector, address(0)));
        vm.prank(enforcer);
        token.forceTransfer(user1, address(0), TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
    }

    function test_ForceTransfer_AdjustsFrozenAmountIfExceedsNewBalance() public {
         vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, MINT_AMOUNT); // Freeze all
        assertEq(token.getFrozen(user1, TOKEN_ID_1), MINT_AMOUNT);

        // Force transfer some tokens, new balance will be less than original frozen amount
        uint256 newBalance = MINT_AMOUNT - FORCE_TRANSFER_AMOUNT;
        vm.prank(enforcer);
        token.forceTransfer(user1, user2, TOKEN_ID_1, FORCE_TRANSFER_AMOUNT);
        
        assertEq(token.balanceOf(user1, TOKEN_ID_1), newBalance);
        // The contract logic: if(_frozenTokens[from][tokenId] > balanceOf(from, tokenId)) _frozenTokens[from][tokenId] = balanceOf(from, tokenId);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), newBalance, "Frozen amount not adjusted correctly");
    }

    // --- Batch Transfer Tests (safeBatchTransferFrom) ---

    function test_SafeBatchTransfer_Success_WhitelistedToWhitelisted() public {
        uint256[] memory ids = new uint256[](2);
        ids[0] = TOKEN_ID_1;
        ids[1] = TOKEN_ID_2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = TRANSFER_AMOUNT;
        amounts[1] = TRANSFER_AMOUNT;

        uint256 user1InitialBalance1 = token.balanceOf(user1, TOKEN_ID_1);
        uint256 user1InitialBalance2 = token.balanceOf(user1, TOKEN_ID_2);
        uint256 user2InitialBalance1 = token.balanceOf(user2, TOKEN_ID_1);
        uint256 user2InitialBalance2 = token.balanceOf(user2, TOKEN_ID_2);

        // OpenZeppelin ERC1155 emits TransferSingle for each item in a batch
        vm.expectEmit(true, true, true, true); 
        emit IERC1155.TransferBatch(user1, user1, user2, ids, amounts);

        vm.prank(user1);
        token.safeBatchTransferFrom(user1, user2, ids, amounts, "");

        assertEq(token.balanceOf(user1, TOKEN_ID_1), user1InitialBalance1 - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user1, TOKEN_ID_2), user1InitialBalance2 - TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_1), user2InitialBalance1 + TRANSFER_AMOUNT);
        assertEq(token.balanceOf(user2, TOKEN_ID_2), user2InitialBalance2 + TRANSFER_AMOUNT);
    }

    function test_SafeBatchTransfer_Success_ToContractReceiver() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = TRANSFER_AMOUNT;

        receiverContract.setShouldReject(false); // Ensure it accepts

        vm.prank(user1);
        token.safeBatchTransferFrom(user1, address(receiverContract), ids, amounts, "");

        assertEq(token.balanceOf(address(receiverContract), TOKEN_ID_1), TRANSFER_AMOUNT);
        // This also tests MockERC1155Receiver.onERC1155BatchReceived success path
    }

    function test_Revert_SafeBatchTransfer_ToContractThatRejects() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = TRANSFER_AMOUNT;

        receiverContract.setShouldReject(true);

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(receiverContract)));
        token.safeBatchTransferFrom(user1, address(receiverContract), ids, amounts, "");
        // This also tests MockERC1155Receiver.onERC1155BatchReceived rejection path
    }

    function test_Revert_SafeBatchTransfer_ArraysLengthMismatch() public {
        uint256[] memory ids = new uint256[](2);
        ids[0] = TOKEN_ID_1;
        ids[1] = TOKEN_ID_2;
        uint256[] memory amounts = new uint256[](1); // Mismatch
        amounts[0] = TRANSFER_AMOUNT;

        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidArrayLength.selector, 2, 1));
        vm.prank(user1);
        token.safeBatchTransferFrom(user1, user2, ids, amounts, "");
    }

    function test_Revert_SafeBatchTransfer_ToZeroAddress() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = TRANSFER_AMOUNT;

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(0)));
        token.safeBatchTransferFrom(user1, address(0), ids, amounts, "");
    }

    function test_Revert_SafeBatchTransfer_FromNotWhitelisted() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = TRANSFER_AMOUNT;

        vm.prank(whitelister);
        token.changeWhitelist(user1, false); 

        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT));
        vm.prank(user1);
        token.safeBatchTransferFrom(user1, user2, ids, amounts, "");
    }

    function test_Revert_SafeBatchTransfer_ToNotWhitelisted() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = TRANSFER_AMOUNT;

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, nonWhitelistedUser, TOKEN_ID_1, TRANSFER_AMOUNT));
        token.safeBatchTransferFrom(user1, nonWhitelistedUser, ids, amounts, "");
    }

    function test_Revert_SafeBatchTransfer_NotApproved() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = TRANSFER_AMOUNT;

        vm.prank(otherUser); // Not approved by user1
        token.setApprovalForAll(user1, false); // Ensure no prior approval for otherUser from user1
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155MissingApprovalForAll.selector, otherUser, user1));
        vm.prank(otherUser); // Not approved by user1
        token.safeBatchTransferFrom(user1, user2, ids, amounts, "");
    }

    function test_Revert_SafeBatchTransfer_InsufficientBalance() public {
        uint256[] memory ids = new uint256[](2);
        ids[0] = TOKEN_ID_1;
        ids[1] = TOKEN_ID_2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = MINT_AMOUNT;       
        amounts[1] = MINT_AMOUNT + 1; // Insufficient for TOKEN_ID_2

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_2, MINT_AMOUNT + 1));
        token.safeBatchTransferFrom(user1, user2, ids, amounts, "");
    }

    function test_Revert_SafeBatchTransfer_WhenFrozen() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT);

        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_ID_1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = (MINT_AMOUNT - FREEZE_AMOUNT) + 1; // Attempt to transfer more than available

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IERC7943.ERC7943NotAllowedTransfer.selector, user1, user2, TOKEN_ID_1, amounts[0]));
        token.safeBatchTransferFrom(user1, user2, ids, amounts, "");
    }

    // --- Freeze/Unfreeze/FrozenAmount Tests ---

    function test_Freeze_Success() public {
        vm.prank(enforcer);
        vm.expectEmit(true, true, true, true);
        emit IERC7943.Frozen(user1, TOKEN_ID_1, FREEZE_AMOUNT);
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), FREEZE_AMOUNT);
    }

    function test_Revert_Freeze_NotEnforcer() public {
        vm.prank(user2); // Not an enforcer
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user2, ENFORCER_ROLE));
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT);
    }

    function test_Revert_Freeze_InsufficientBalance() public {
        uint256 excessiveAmount = MINT_AMOUNT + 1;
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InsufficientBalance.selector, user1, token.balanceOf(user1, TOKEN_ID_1), excessiveAmount, TOKEN_ID_1));
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, excessiveAmount);
    }

    function test_Unfreeze_Success() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT); // Freeze first

        vm.expectEmit(true, true, true, true);
        emit IERC7943.Frozen(user1, TOKEN_ID_1, 0);
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, 0);
        assertEq(token.getFrozen(user1, TOKEN_ID_1), 0);
    }

    function test_Revert_Unfreeze_NotEnforcer() public {
        vm.prank(enforcer);
        token.setFrozen(user1, TOKEN_ID_1, FREEZE_AMOUNT); 

        vm.prank(user2); // Not an enforcer
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user2, ENFORCER_ROLE));
        token.setFrozen(user1, TOKEN_ID_1, 0);
    }

    // --- Interface Support Tests ---

    function test_Interface_SupportsIERC7943() public view {
        assertTrue(token.supportsInterface(type(IERC7943).interfaceId));
    }

    function test_Interface_SupportsIERC1155() public view {
        assertTrue(token.supportsInterface(type(IERC1155).interfaceId));
    }

    function test_Interface_SupportsIERC165() public view {
        assertTrue(token.supportsInterface(type(IERC165).interfaceId));
    }

    function test_Interface_SupportsAccessControl() public view {
        assertTrue(token.supportsInterface(type(IAccessControlEnumerable).interfaceId));
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

    function test_AccessControl_RenounceRole_Success() public {
        vm.prank(admin);
        token.grantRole(MINTER_ROLE, user1);
        assertTrue(token.hasRole(MINTER_ROLE, user1));

        vm.prank(user1); 
        vm.expectEmit(true, false, false, true);
        emit IAccessControl.RoleRevoked(MINTER_ROLE, user1, user1);
        token.renounceRole(MINTER_ROLE, user1);
        
        assertFalse(token.hasRole(MINTER_ROLE, user1));
    }

    function test_Revert_AccessControl_RenounceRole_NotSelf() public {
        vm.prank(admin); // admin tries to renounce role for 'minter'
        vm.expectRevert(IAccessControl.AccessControlBadConfirmation.selector);
        token.renounceRole(MINTER_ROLE, minter); 
    }

    // --- isTransferAllowed Tests ---

    function test_IsTransferAllowed_Success() public view {
        assertTrue(token.isTransferAllowed(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT));
    }

    function test_IsTransferAllowed_Fail_InsufficientBalance() public view {
        assertFalse(token.isTransferAllowed(user1, user2, TOKEN_ID_1, MINT_AMOUNT + 1));
    }

    function test_IsTransferAllowed_Fail_FromNotWhitelisted() public {
        vm.prank(whitelister);
        token.changeWhitelist(user1, false);
        assertFalse(token.isTransferAllowed(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT));
    }

    function test_IsTransferAllowed_Fail_ToNotWhitelisted() public view {
        assertFalse(token.isTransferAllowed(user1, nonWhitelistedUser, TOKEN_ID_1, TRANSFER_AMOUNT));
    }
    
    function test_IsTransferAllowed_Fail_FrozenAmountExceedsTransferable() public {
        vm.prank(enforcer);
        // Freeze an amount such that TRANSFER_AMOUNT is no longer possible
        uint256 amountToFreeze = MINT_AMOUNT - TRANSFER_AMOUNT + 1;
        if (amountToFreeze > MINT_AMOUNT) amountToFreeze = MINT_AMOUNT; // Cannot freeze more than balance
        token.setFrozen(user1, TOKEN_ID_1, amountToFreeze);
        assertFalse(token.isTransferAllowed(user1, user2, TOKEN_ID_1, TRANSFER_AMOUNT));
        
    }

    // --- isUserAllowed Tests ---
    function test_IsUserAllowed_Success() public view {
        assertTrue(token.isUserAllowed(user1));
    }

    function test_IsUserAllowed_Fail_NotWhitelisted() public view {
        assertFalse(token.isUserAllowed(nonWhitelistedUser));
    }
}