// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {uRWA20Metadata} from "../contracts/modules/erc20/uRWA20Metadata.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract URWA20MetadataTest is Test {
    uRWA20Metadata internal token;
    address internal admin = makeAddr("admin");
    address internal stranger = makeAddr("stranger");

    function setUp() public {
        token = new uRWA20Metadata("Metadata RWA", "MRWA", admin);
    }

    function test_SetDocument_OnlyDocumentRole() public {
        bytes32 role = token.DOCUMENT_ROLE();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, role));
        token.setDocument("prospectus", "ipfs://a", bytes32(uint256(1)));
    }

    function test_RemoveDocument_OnlyDocumentRole() public {
        vm.prank(admin);
        token.setDocument("prospectus", "ipfs://a", bytes32(uint256(1)));
        bytes32 role = token.DOCUMENT_ROLE();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, role));
        token.removeDocument("prospectus");
    }

    function test_SetDocument_UpdateDoesNotListTwice() public {
        vm.startPrank(admin);
        token.setDocument("prospectus", "ipfs://a", bytes32(uint256(1)));
        token.setDocument("prospectus", "ipfs://b", bytes32(uint256(2)));
        vm.stopPrank();
        assertEq(token.getAllDocuments().length, 1);
        (string memory uri, , ) = token.getDocument("prospectus");
        assertEq(uri, "ipfs://b");
    }

    /// @dev Removing a document that is not last must keep the moved document removable.
    function test_RemoveDocument_KeepsIndexConsistent() public {
        vm.startPrank(admin);
        token.setDocument("a", "ipfs://a", bytes32(0));
        token.setDocument("b", "ipfs://b", bytes32(0));
        token.setDocument("c", "ipfs://c", bytes32(0));
        token.removeDocument("a"); // "c" moves into slot 0
        token.removeDocument("c");
        vm.stopPrank();
        bytes32[] memory names = token.getAllDocuments();
        assertEq(names.length, 1);
        assertEq(names[0], bytes32("b"));
    }

    function test_RemoveDocument_UnknownReverts() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(uRWA20Metadata.DocumentNotFound.selector, bytes32("missing")));
        token.removeDocument("missing");
    }
}
