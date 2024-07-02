// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IPBT.sol";
import "./ERC721ReadOnly.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

error InvalidSignature();
error NoMappedTokenForChip();
error NoMintedTokenForChip();
error ArrayLengthMismatch();
error SeedingChipDataForExistingToken();
error UpdatingUnmintedChip();
error InvalidBlockNumber();
error BlockNumberTooOld();
error NoSetTokenIdForChip();
error DigestTimestampInFuture();
error DigestTimestampTooOld();

/**
 * Implementation of PBT where all chipId->tokenIds are preset in the contract by the contract owner.
 */
contract PBTSimple is ERC721ReadOnly, IPBT {
    using SignatureChecker for address;
    using ECDSA for bytes32;

    /* ============ State Variables ============ */

    mapping(address chipId => uint256 tokenId) public chipIdToTokenId;
    mapping(uint256 tokenId => address chipId) public tokenIdToChipId;
    uint256 public immutable maxDurationWindow; // Amount of time after which chip signatures are expired
    mapping(address chipId => uint256 nonce) public previousNonce; // Maps chipId to previous nonce

    /* ============ Constructor ============ */

    /**
     * @dev Constructor for ClaimedPBT. Sets the name and symbol for the token.
     *
     * @param name              The name of the token
     * @param symbol            The symbol of the token
     * @param _maxDuratioWindow   The maximum amount of blocks a signature used for updating chip table is valid for
     */
    constructor(string memory name, string memory symbol, uint256 _maxDuratioWindow) ERC721ReadOnly(name, symbol) {
        maxDurationWindow = _maxDuratioWindow;
    }

    /* ============ External Functions ============ */

    /**
     * @notice Included for compliance with legacy transfer function but left unimplemented to ensure usage of new transfer function.
     */
    function transferTokenWithChip(bytes calldata signatureFromChip, uint256 blockNumberUsedInSig) public override {
        transferTokenWithChip(signatureFromChip, blockNumberUsedInSig, false);
    }

    function transferTokenWithChip(
        bytes calldata, /*signatureFromChip*/
        uint256, /*blockNumberUsedInSig*/
        bool /*useSafeTransfer*/
    ) public virtual {}

    /**
     * @notice Allow a user to transfer a chip to a new owner with additional checks. The signature should be signed by the chip.
     *
     * @param chipId                Chip ID (address) of chip being transferred
     * @param signatureFromChip     Signature of keccak256(msg.sender, blockhash(blockNumberUsedInSig), payload) signed by chip
     *                              being transferred
     * @param timestampInSig        Timestamp used in signature
     * @param useSafeTransfer       Indicates whether to use safeTransferFrom or transferFrom
     * @param payload               Encoded payload containing data that can be used to determine how to execute the transfer. This
     *                              param can be leveraged to add additional logic/context when PBT is transferred.
     */
    function transferToken(
        address chipId,
        bytes calldata signatureFromChip,
        uint256 timestampInSig,
        bool useSafeTransfer,
        bytes calldata payload
    ) public virtual {
        if (!_exists(tokenIdFor(chipId))) {
            revert NoMintedTokenForChip();
        }

        bytes32 signedHash = _createSignedHash(timestampInSig, chipId, msg.sender);
        if (!SignatureChecker.isValidSignatureNow(chipId, signedHash, signatureFromChip)) {
            revert InvalidSignature();
        }
        previousNonce[chipId] = uint256(signedHash) ^ uint256(blockhash(block.number - 1));

        // ChipInfo memory chipInfo = chipTable[chipId];
        uint256 tokenId = tokenIdFor(chipId);
        address chipOwner = ownerOf(tokenId);

        _transferPBT(chipOwner, tokenId, useSafeTransfer);
    }

    /* ============ View Functions ============ */

    /**
     * @dev Using OpenZeppelin's SignatureChecker library, checks if the signature is valid for the payload. Library is
     * ERC-1271 compatible, so it will check if the chipId is a contract and if so, if it implements the isValidSignature.
     *
     * @param tokenId      The tokenId to check the signature for
     * @param payload      The payload to check the signature for
     * @param signature    The signature to check
     * @return bool        If the signature is valid, false otherwise
     */
    function isChipSignatureForToken(uint256 tokenId, bytes calldata payload, bytes calldata signature)
        public
        view
        returns (bool)
    {
        bytes32 payloadHash = keccak256(abi.encodePacked(payload)).toEthSignedMessageHash();
        address chipId = tokenIdToChipId[tokenId];
        return chipId.isValidSignatureNow(payloadHash, signature);
    }

    /**
     * @dev Returns the minted tokenId for a given chipId
     *
     * @param chipId       The chipId to get the tokenId for
     * @return tokenId     The tokenId for the given chipId
     */
    function tokenIdFor(address chipId) public view returns (uint256) {
        uint256 tokenId = chipIdToTokenId[chipId];
        if (!_exists(tokenId)) {
            revert NoMintedTokenForChip();
        }
        return tokenId;
    }

    /* ============ Internal Functions ============ */

    /**
     * @dev Mints a new token and assigns it to the given address. Also adds the chipId to the tokenIdToChipId mapping,
     * adds the ChipInfo to the chipTable, and increments the tokenIdCounter.
     *
     * @param to                        The address to mint the token to
     * @param chipId                    The chipId to mint the token for
     * @param signatureFromChip         The signature from the chip to validate the mint
     * @param timestampInSig            Timestamp used in signature
     * @return uint256                  The tokenId of the newly minted token
     */
    function _mint(address to, address chipId, bytes calldata signatureFromChip, uint256 timestampInSig)
        internal
        virtual
        returns (uint256)
    {
        bytes32 signedHash = _createSignedHash(timestampInSig, chipId, to);
        if (!SignatureChecker.isValidSignatureNow(chipId, signedHash, signatureFromChip)) {
            revert InvalidSignature();
        }
        previousNonce[chipId] = uint256(signedHash) ^ uint256(blockhash(block.number - 1));

        uint256 tokenId = chipIdToTokenId[chipId];
        // if (!tokenId) {
        //     revert NoSetTokenIdForChip();
        // }

        _mint(to, tokenId);
        emit PBTMint(tokenId, chipId);

        return tokenId;
    }

    /**
     * @dev Create a signed hash using the timestampInSig and payload.
     *
     * @param timestampInSig               Timestamp in signature
     * @param chipId                       ChipId used in signature
     * @param nftRecipient                 Address of the nft recipient
     * @return boolean
     */
    function _createSignedHash(uint256 timestampInSig, address chipId, address nftRecipient)
        internal
        virtual
        returns (bytes32)
    {

        if (timestampInSig > block.timestamp) revert DigestTimestampInFuture();
        if (timestampInSig < block.timestamp - maxDurationWindow) revert DigestTimestampTooOld();

        return keccak256(abi.encode(address(this), block.chainid, previousNonce[chipId], nftRecipient, timestampInSig));
    }

    /**
     * @notice Handle transfer of PBT inclusing whether to transfer using safeTransfer. The to address is always the msg.sender.
     *
     * @param from                 Address of owner transferring PBT
     * @param tokenId              ID of PBT being transferred
     * @param useSafeTransfer      Indicates whether to use safeTransferFrom or transferFrom
     */
    function _transferPBT(address from, uint256 tokenId, bool useSafeTransfer) internal {
        if (useSafeTransfer) {
            _safeTransfer(from, msg.sender, tokenId, "");
        } else {
            _transfer(from, msg.sender, tokenId);
        }
    }

    /**
     * @dev Should only be called for tokenIds that have not yet been minted.
     * If the tokenId has already been minted, use _updateChips instead.
     *
     * @param chipIds        Array of chipIds that will be mapped to tokenIds
     * @param tokenIds       Array of tokenIds to map the chipIds
     */
    function _seedChipToTokenMapping(address[] memory chipIds, uint256[] memory tokenIds) internal {
        _seedChipToTokenMapping(chipIds, tokenIds, true);
    }

    function _seedChipToTokenMapping(
        address[] memory chipIds,
        uint256[] memory tokenIds,
        bool throwIfTokenAlreadyMinted
    ) internal {
        uint256 tokenIdsLength = tokenIds.length;
        if (tokenIdsLength != chipIds.length) {
            revert ArrayLengthMismatch();
        }
        for (uint256 i = 0; i < tokenIdsLength; ++i) {
            address chipId = chipIds[i];
            uint256 tokenId = tokenIds[i];

            if (throwIfTokenAlreadyMinted && _exists(tokenId)) {
                revert SeedingChipDataForExistingToken();
            }

            chipIdToTokenId[chipId] = tokenId;
            tokenIdToChipId[tokenId] = chipId;
        }
    }

    /**
     * @dev Should only be called for tokenIds that have been minted
     * If the tokenId hasn't been minted yet, use _seedChipToTokenMapping instead
     * Should only be used and called with care and rails to avoid a centralized entity swapping out valid chips.
     *
     * @param chipIdsOld       Array of old chipIds to change the mapping of token to a new chipId
     * @param chipIdsNew       Array of new chipIds to replace tokenId mapping of old chipIds
     */
    function _updateChips(address[] calldata chipIdsOld, address[] calldata chipIdsNew) internal {
        if (chipIdsOld.length != chipIdsNew.length) {
            revert ArrayLengthMismatch();
        }

        for (uint256 i = 0; i < chipIdsOld.length; ++i) {
            address oldChipId = chipIdsOld[i];

            // if (!tokenIdFor(oldChipId)) {
            //     revert UpdatingUnmintedChip();
            // }

            address newChipId = chipIdsNew[i];
            uint256 tokenId = chipIdToTokenId[oldChipId];
            chipIdToTokenId[newChipId] = tokenId;
            tokenIdToChipId[tokenId] = newChipId;
            if (_exists(tokenId)) {
                emit PBTChipRemapping(tokenId, oldChipId, newChipId);
            }

            delete chipIdToTokenId[oldChipId];
        }
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IPBT).interfaceId || super.supportsInterface(interfaceId);
    }
}
