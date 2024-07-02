// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/mocks/PBTSimpleMock.sol";

contract PBTSimpleTest is Test {
    event PBTMint(uint256 indexed tokenId, address indexed chipAddress);
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event PBTChipRemapping(uint256 indexed tokenId, address indexed oldChipId, address indexed newChipId);

    PBTSimpleMock public pbt;
    uint256 public tokenId1 = 1;
    uint256 public tokenId2 = 2;
    uint256 public tokenId3 = 3;
    address public user1 = vm.addr(1);
    address public user2 = vm.addr(2);
    address public user3 = vm.addr(3);
    address public chipAddr1 = vm.addr(101);
    address public chipAddr2 = vm.addr(102);
    address public chipAddr3 = vm.addr(103);
    address public chipAddr4 = vm.addr(104);
    uint256 public timestamp = block.timestamp;

    function setUp() public {
        pbt = new PBTSimpleMock("PBTSimple", "PBTS", 10000); // maxDurationWindow of 10000 seconds
    }

    function _createSignature(uint256 timestampInSig, address chipId, address to, uint256 chipAddrNum) private returns (bytes memory signature) {
        bytes32 payloadHash = keccak256(abi.encodePacked(timestampInSig, chipId, to));
        bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(chipAddrNum, signedHash);
        signature = abi.encodePacked(r, s, v);
    }


    modifier mintedTokens() {
        address[] memory chipAddresses = new address[](2);
        chipAddresses[0] = chipAddr1;
        chipAddresses[1] = chipAddr2;

        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = tokenId1;
        tokenIds[1] = tokenId2;

        pbt.seedChipToTokenMapping(chipAddresses, tokenIds, true);
        pbt.mint(chipAddr1, _createSignature(timestamp, chipAddr1, user1, 101), timestamp);
        pbt.mint(chipAddr2, _createSignature(timestamp, chipAddr2, user1, 102), timestamp);
        _;
    }

    function testSeedChipToTokenMappingInvalidInput() public {
        address[] memory chipAddresses = new address[](2);
        chipAddresses[0] = chipAddr1;
        chipAddresses[1] = chipAddr2;

        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId1;

        vm.expectRevert(ArrayLengthMismatch.selector);
        pbt.seedChipToTokenMapping(chipAddresses, tokenIds, true);
    }
    
    function testSeedChipToTokenMappingExistingToken() public mintedTokens {
        address[] memory chipAddresses = new address[](2);
        chipAddresses[0] = chipAddr1;
        chipAddresses[1] = chipAddr2;

        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = tokenId1;
        tokenIds[1] = tokenId2;

        vm.expectRevert(SeedingChipDataForExistingToken.selector);
        pbt.seedChipToTokenMapping(chipAddresses, tokenIds, true);

        // This call will succeed because the flag is set to false
        pbt.seedChipToTokenMapping(chipAddresses, tokenIds, false);
    }

    function testSeedChipToTokenMapping() public {
        address[] memory chipAddresses = new address[](2);
        chipAddresses[0] = chipAddr1;
        chipAddresses[1] = chipAddr2;

        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = tokenId1;
        tokenIds[1] = tokenId2;

        pbt.seedChipToTokenMapping(chipAddresses, tokenIds, true);

        assertEq(pbt.getTokenData(chipAddr1), tokenId1);
        assertEq(pbt.getTokenData(chipAddr2), tokenId2);
    }

    function testUpdateChipsInvalidInput() public {
        address[] memory chipAddressesOld = new address[](2);
        chipAddressesOld[0] = chipAddr1;
        chipAddressesOld[1] = chipAddr2;

        address[] memory chipAddressesNew = new address[](1);
        chipAddressesNew[0] = chipAddr3;

        vm.expectRevert(ArrayLengthMismatch.selector);
        pbt.updateChips(chipAddressesOld, chipAddressesNew);
    }

    function testUpdateChipsUnsetChip() public {
        address[] memory chipAddressesOld = new address[](2);
        chipAddressesOld[0] = chipAddr1;
        chipAddressesOld[1] = chipAddr2;

        address[] memory chipAddressesNew = new address[](2);
        chipAddressesNew[0] = chipAddr3;
        chipAddressesNew[1] = chipAddr4;

        vm.expectRevert(UpdatingUnmintedChip.selector);
        pbt.updateChips(chipAddressesOld, chipAddressesNew);
    }

    function testUpdateChips() public mintedTokens {
        address[] memory chipAddressesOld = new address[](2);
        chipAddressesOld[0] = chipAddr1;
        chipAddressesOld[1] = chipAddr2;

        address[] memory chipAddressesNew = new address[](2);
        chipAddressesNew[0] = chipAddr3;
        chipAddressesNew[1] = chipAddr4;

        pbt.updateChips(chipAddressesOld, chipAddressesNew);

        assertEq(pbt.getTokenData(chipAddr3), tokenId1);
        assertEq(pbt.getTokenData(chipAddr4), tokenId2);
    }

    function testTokenIdFor() public {
        vm.expectRevert(NoMappedTokenForChip.selector);
        pbt.tokenIdFor(chipAddr1);
    }

    function testTokenIdForMinted() public mintedTokens {
        assertEq(pbt.tokenIdFor(chipAddr1), tokenId1);
    }

    function testIsChipSignatureForToken() public mintedTokens {
        bytes memory payload = abi.encodePacked("ThisIsPBTSimple");
        bytes memory chipSignature = createSignature(chipAddr1, user1);

        assertEq(pbt.isChipSignatureForToken(tokenId1, payload, chipSignature), true);
    }

    function testTransferToken() public mintedTokens {
        // User2 will transfer tokenId2 to User3
        bytes memory payload = abi.encodePacked(user3);
        bytes memory chipSignature = createSignature(chipAddr2, user2);

        vm.prank(user2);
        vm.expectEmit(true, true, true, true);
        emit Transfer(user2, user3, tokenId2);

        pbt.transferToken(chipAddr2, chipSignature, timestamp, false, payload);

        assertEq(pbt.balanceOf(user2), 1);
        assertEq(pbt.balanceOf(user3), 1);
        assertEq(pbt.ownerOf(tokenId2), user3);
    }

    function createSignature(address chipId, address user) private returns (bytes memory) {
        bytes32 signedHash = keccak256(abi.encode(address(pbt), block.chainid, pbt.previousNonce(chipId), user, timestamp));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(uint160(chipId)), signedHash);
        return abi.encodePacked(r, s, v);
    }
}
