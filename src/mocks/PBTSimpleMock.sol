// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../PBTSimple.sol";


contract PBTSimpleMock is PBTSimple {
    constructor(
        string memory name, 
        string memory symbol,
        uint256 maxBlockWindow
    ) 
        PBTSimple(name, symbol, maxBlockWindow) 
    {}

    function seedChipToTokenMapping(
        address[] memory chipAddresses,
        uint256[] memory tokenIds,
        bool throwIfTokenAlreadyMinted
    ) public {
        _seedChipToTokenMapping(chipAddresses, tokenIds, throwIfTokenAlreadyMinted);
    }

    function getTokenData(address chipId) public view returns (TokenData memory) {
        return chipIdTokenData[chipId];
    }

    function updateChips(address[] calldata chipAddressesOld, address[] calldata chipAddressesNew) public {
        _updateChips(chipAddressesOld, chipAddressesNew);
    }

    function mint(bytes calldata signatureFromChip, uint256 blockNumberUsedInSig, address chipId)
        public
        returns (uint256)
    {
        return _mint(msg.sender(), chipId, signatureFromChip, blockNumberUsedInSig);
    }
}
