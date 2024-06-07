// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @dev Contract for PBTs (Physical Backed Tokens).
 * NFTs that are backed by a physical asset, through a chip embedded in the physical asset.
 */
interface IPBT {
    /// @notice Returns the token id for a given chip address.
    /// @dev Throws if there is no existing token for the chip in the collection.
    /// @param chipAddress The address for the chip embedded in the physical item (computed from the chip's public key).
    /// @return The token id for the passed in chip address.
    function tokenIdFor(address chipAddress) external view returns (uint256);

    /// @notice Returns true if the chip for the specified token id is the signer of the signature of the payload.
    /// @dev Throws if tokenId does not exist in the collection.
    /// @param tokenId The token id.
    /// @param payload Arbitrary data that is signed by the chip to produce the signature param.
    /// @param signature Chip's signature of the passed-in payload.
    /// @return Whether the signature of the payload was signed by the chip linked to the token id.
    function isChipSignatureForToken(uint256 tokenId, bytes calldata payload, bytes calldata signature)
        external
        view
        returns (bool);

    /// @notice Transfers the token into the message sender's wallet.
    /// @param chipId Chip ID (address) of chip being transferred.
    /// @param signatureFromChip An EIP-191 signature of (msgSender, blockhash), where blockhash is the block hash for blockNumberUsedInSig.
    /// @param timestampInSig The timestamp signed in signatureFromChip.
    /// @param useSafeTransferFrom Whether EIP-721's safeTransferFrom should be used in the implementation, instead of transferFrom.
    /// @param payload Encoded payload containing data that can be used to determine how to execute the transfer. This param can be leveraged to add additional logic/context when PBT is transferred.
    ///
    /// @dev The implementation should check that block number be reasonably recent to avoid replay attacks of stale signatures.
    /// The implementation should also verify that the address signed in the signature matches msgSender.
    /// The implementation should also verify that the signatureFromChip was signed by the passed-in chipId.
    /// If the address recovered from the signature matches a chip address that's bound to an existing token, the token should be transferred to msgSender.
    /// If there is no existing token linked to the chip, the function should error.
    function transferToken(
        address chipId,
        bytes calldata signatureFromChip,
        uint256 timestampInSig,
        bool useSafeTransferFrom,
        bytes calldata payload
    ) external;

    /// @notice This function is considered legacy. It is optional, only if you want to support legacy PBTs.
    /// @param signatureFromChip An EIP-191 signature of (msgSender, blockhash), where blockhash is the block hash for blockNumberUsedInSig.
    /// @param blockNumberUsedInSig The block number linked to the blockhash signed in signatureFromChip. Should be a recent block number.
    /// @param useSafeTransferFrom Whether EIP-721's safeTransferFrom should be used in the implementation, instead of transferFrom.
    ///
    /// @dev The implementation should check that block number be reasonably recent to avoid replay attacks of stale signatures.
    /// The implementation should also verify that the address signed in the signature matches msgSender.
    /// If the address recovered from the signature matches a chip address that's bound to an existing token, the token should be transferred to msgSender.
    /// If there is no existing token linked to the chip, the function should error.
    function transferTokenWithChip(
        bytes calldata signatureFromChip,
        uint256 blockNumberUsedInSig,
        bool useSafeTransferFrom
    ) external;

    /// @notice This function is considered legacy. It is optional, only if you want to support legacy PBTs.
    /// @notice Calls transferTokenWithChip as defined above, with useSafeTransferFrom set to false.
    function transferTokenWithChip(bytes calldata signatureFromChip, uint256 blockNumberUsedInSig) external;

    /// @notice Emitted when a token is minted.
    event PBTMint(uint256 indexed tokenId, address indexed chipAddress);

    /// @notice Emitted when a token is mapped to a different chip.
    /// Chip replacements may be useful in certain scenarios (e.g. chip defect).
    event PBTChipRemapping(uint256 indexed tokenId, address indexed oldChipAddress, address indexed newChipAddress);
}
