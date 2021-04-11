// SPDX-License-Identifier: MIT

pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import {SafeMath} from "./crypto/SafeMath.sol";
import {BytesLib} from "./crypto/BytesLib.sol";
import {CryptoUtils} from "./crypto/CryptoUtils.sol";
import {ValidateSPV} from "./crypto/ValidateSPV.sol";
import {IRelay} from "./IRelay.sol";
import {Parser} from "./crypto/Parser.sol";
import "./Ownable.sol";

/// @title BTC Relay
contract Relay is IRelay, Parser, Ownable {
    using SafeMath for uint256;
    using BytesLib for bytes;
    using CryptoUtils for bytes;
    struct Header {
        // height of this block header (cannot be zero)
        uint32 height;
        // identifier of chain fork
        uint64 chainId;
    }

    uint uuid = 1;
    struct Txdata {
        // BTC Tx hex
        bytes txhex;
        // Ethereum address
        address ethAddress;
        // BTC To address
        bytes toaddress;
        // BTC Tx hash
        bytes txid;
        // BTC Tx amount
        uint256 amount;
        // uuid
        uint uuid;
        //transferred
        bool transferred;
    }
    mapping(uint => Txdata) txsInformation;
    mapping(address => uint[]) pendingMints;
    uint[] allPendingMints;
    uint[] allCompletedMints;
    mapping(address => uint[]) completedMints;
    mapping(bytes => uint) relaysMapped;

    // mapping of block hashes to block headers (ALL ever submitted, i.e., incl. forks)
    mapping(bytes32 => Header) public _headers;
    // main chain mapping for constant time inclusion check
    mapping(uint32 => bytes32) public _chain;

    struct Fork {
        uint32 height; // best height of fork
        bytes32 ancestor; // branched from this
        bytes32[] descendants; // references to submitted block headers
    }

    // mapping of ids to forks
    mapping(uint256 => Fork) public _forks;

    // incrementing counter to track forks
    // OPTIMIZATION: default to zero value
    uint256 private _chainCounter;

    // target of the difficulty period
    uint256 public _epochStartTarget;
    uint256 public _epochEndTarget;

    uint64 public _epochStartTime;
    uint64 public _epochEndTime;

    // block with the most accumulated work, i.e., blockchain tip
    uint32 internal _bestHeight;
    bytes32 internal _bestBlock;
    uint32 internal _currHeight;
    bytes32 internal _currBlock;

    // CONSTANTS
    uint256 public constant DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
    uint256 public constant MAIN_CHAIN_ID = 0;
    uint256 public constant CONFIRMATIONS = 6;

    // EXCEPTION MESSAGES
    // OPTIMIZATION: limit string length to 32 bytes
    string constant ERR_INVALID_HEADER_SIZE = "Invalid block header size";
    string constant ERR_INVALID_GENESIS_HEIGHT = "Invalid genesis height";
    string constant ERR_INVALID_HEADER_BATCH = "Invalid block header batch";
    string constant ERR_DUPLICATE_BLOCK = "Block already stored";
    string constant ERR_PREVIOUS_BLOCK = "Previous block hash not found";
    string constant ERR_LOW_DIFFICULTY = "Insufficient difficulty";
    string constant ERR_DIFF_TARGET_HEADER = "Incorrect difficulty target";
    string constant ERR_DIFF_PERIOD = "Invalid difficulty period";
    string constant ERR_NOT_EXTENSION = "Not extension of chain";
    string constant ERR_BLOCK_NOT_FOUND = "Block not found";
    string constant ERR_CONFIRMS = "Insufficient confirmations";
    string constant ERR_VERIFY_TX = "Incorrect merkle proof";
    string constant ERR_INVALID_TXID = "Invalid tx identifier";
    string constant ERR_INVALID_AMOUNT = "Invalid amount";
    string constant ERR_RELAY_MAPPED = "Relay data is already mapped";
    string constant ERR_MINTID_NOT_FOUND = "Corresponding minting id not found";
    string constant ERR_MINTID_INVALID = "Invalid Mint Id";

    uint256 public data;


    /**
    * @notice Initializes the relay with the provided block.
    * @param header Genesis block header
    * @param height Genesis block height
    */
    constructor(
        bytes memory header,
        uint32 height
    ) public {
        data = abi.decode(header, (uint256));
        require(header.length == 80, ERR_INVALID_HEADER_SIZE);
        require(height > 0, ERR_INVALID_GENESIS_HEIGHT);
        bytes32 digest = header.hash256();
        uint256 target = header.extractTarget();
        uint64 timestamp = header.extractTimestamp();
        uint256 chainId = MAIN_CHAIN_ID;

        _bestBlock = digest;
        _bestHeight = height;
        _currHeight = height;
        _currBlock = digest;

        _forks[chainId].height = height;
        _chain[height] = digest;

        _epochStartTarget = target;
        _epochStartTime = timestamp;
        _epochEndTarget = target;
        _epochEndTime = timestamp;

        _storeBlockHeader(
            digest,
            height,
            chainId
        );
    }

    /**
     * @dev Core logic for block header validation
     */
    function _submitBlockHeader(bytes memory header) internal virtual {
        require(header.length == 80, ERR_INVALID_HEADER_SIZE);

        // Fail if block already exists
        bytes32 hashCurrBlock = header.hash256();
        require(_headers[hashCurrBlock].height == 0, ERR_DUPLICATE_BLOCK);

        // Fail if previous block hash not in current state of main chain
        bytes32 hashPrevBlock = header.extractPrevBlockLE().toBytes32();
        require(_headers[hashPrevBlock].height > 0, ERR_PREVIOUS_BLOCK);

        uint256 target = header.extractTarget();

        // Check the PoW solution matches the target specified in the block header
        require(abi.encodePacked(hashCurrBlock).reverseEndianness().bytesToUint() <= target, ERR_LOW_DIFFICULTY);

        uint32 height = 1 + _headers[hashPrevBlock].height;
        _currHeight = height;
        _currBlock = hashCurrBlock;

        // Check the specified difficulty target is correct
        if (_isPeriodStart(height)) {
            require(isCorrectDifficultyTarget(
                    _epochStartTarget,
                    _epochStartTime,
                    _epochEndTarget,
                    _epochEndTime,
                    target
                ), ERR_DIFF_TARGET_HEADER);

            _epochStartTarget = target;
            _epochStartTime = header.extractTimestamp();

            delete _epochEndTarget;
            delete _epochEndTime;
        } else if (_isPeriodEnd(height)) {
            // only update if end to save gas
            _epochEndTarget = target;
            _epochEndTime = header.extractTimestamp();
        }

        uint256 chainId = _headers[hashPrevBlock].chainId;
        bool isNewFork = _forks[chainId].height != _headers[hashPrevBlock].height;

        if (isNewFork) {
            chainId = _incrementChainCounter();
            _initializeFork(hashCurrBlock, hashPrevBlock, chainId, height);

            _storeBlockHeader(
                hashCurrBlock,
                height,
                chainId
            );
        } else {
            _storeBlockHeader(
                hashCurrBlock,
                height,
                chainId
            );

            if (chainId == MAIN_CHAIN_ID) {
                _bestBlock = hashCurrBlock;
                _bestHeight = height;

                // extend height of main chain
                _forks[chainId].height = height;
                _chain[height] = hashCurrBlock;

            } else if (height >= _bestHeight + CONFIRMATIONS) {
                // with sufficient confirmations, reorg
                _reorgChain(chainId, height, hashCurrBlock);

            } else {
                // extend fork
                _forks[chainId].height = height;
                _forks[chainId].descendants.push(hashCurrBlock);

            }
        }
    }

    /**
     * @dev See {IRelay-submitBlockHeader}.
     */
    function submitBlockHeader(bytes calldata header) external onlyOwner override {
        _submitBlockHeader(header);
    }

    /**
     * @dev See {IRelay-submitBlockHeaderBatch}.
     */
    function submitBlockHeaderBatch(bytes calldata headers) external onlyOwner override {
        require(headers.length % 80 == 0, ERR_INVALID_HEADER_BATCH);

        for (uint256 i = 0; i < headers.length / 80; i = i.add(1)) {
            bytes memory header = headers.slice(i.mul(80), 80);
            _submitBlockHeader(header);
        }
    }

    function _storeBlockHeader(
        bytes32 digest,
        uint32 height,
        uint256 chainId
    ) internal {
        _chain[height] = digest;
        _headers[digest].height = height;
        _headers[digest].chainId = uint64(chainId);
        emit StoreHeader(digest, height);
    }

    function _incrementChainCounter() internal returns (uint256) {
        _chainCounter = _chainCounter.add(1);
        return _chainCounter;
    }

    function _initializeFork(bytes32 hashCurrBlock, bytes32 hashPrevBlock, uint chainId, uint32 height) internal {
        bytes32[] memory descendants = new bytes32[](1);
        descendants[0] = hashCurrBlock;

        _forks[chainId].height = height;
        _forks[chainId].ancestor = hashPrevBlock;
        _forks[chainId].descendants = descendants;
    }

    function _reorgChain(uint chainId, uint32 height, bytes32 hashCurrBlock) internal {
        // reorg fork to main
        uint256 ancestorId = chainId;
        uint256 forkId = _incrementChainCounter();
        uint32 forkHeight = height - 1;

        // TODO: add new fork struct for old main

        while (ancestorId != MAIN_CHAIN_ID) {
            for (uint i = _forks[ancestorId].descendants.length; i > 0; i--) {
                // get next descendant in fork
                bytes32 descendant = _forks[ancestorId].descendants[i-1];
                // promote header to main chain
                _headers[descendant].chainId = uint64(MAIN_CHAIN_ID);
                // demote old header to new fork
                _headers[_chain[height]].chainId = uint64(forkId);
                // swap header at height
                _chain[height] = descendant;
                forkHeight--;
            }

            bytes32 ancestor = _forks[ancestorId].ancestor;
            ancestorId = _headers[ancestor].chainId;
        }

        emit ChainReorg(_bestBlock, hashCurrBlock, chainId);

        _bestBlock = hashCurrBlock;
        _bestHeight = height;

        delete _forks[chainId];

        // extend to current head
        _chain[_bestHeight] = _bestBlock;
        _headers[_bestBlock].chainId = uint64(MAIN_CHAIN_ID);
    }

    /**
     * @notice Checks if the difficulty target should be adjusted at this block height
     * @param height Block height to be checked
     * @return True if block height is at difficulty adjustment interval, otherwise false
     */
    function _isPeriodStart(uint32 height) internal pure returns (bool){
        return height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0;
    }

    function _isPeriodEnd(uint32 height) internal pure returns (bool){
        return height % DIFFICULTY_ADJUSTMENT_INTERVAL == 2015;
    }

    /**
     * @notice Validates difficulty interval
     * @dev Reverts if previous period invalid
     * @param prevStartTarget Period starting target
     * @param prevStartTime Period starting timestamp
     * @param prevEndTarget Period ending target
     * @param prevEndTime Period ending timestamp
     * @param nextTarget Next period starting target
     * @return True if difficulty level is valid
     */
    function isCorrectDifficultyTarget(
        uint256 prevStartTarget,
        uint64 prevStartTime,
        uint256 prevEndTarget,
        uint64 prevEndTime,
        uint256 nextTarget
    ) public pure returns (bool) {
        require(
            BTCUtils.calculateDifficulty(prevStartTarget) == BTCUtils.calculateDifficulty(prevEndTarget),
            ERR_DIFF_PERIOD
        );

        uint256 expectedTarget = BTCUtils.retargetAlgorithm(
            prevStartTarget,
            prevStartTime,
            prevEndTime
        );

        return (nextTarget & expectedTarget) == nextTarget;
    }

    /**
     * @dev See {IRelay-getBlockHeight}.
     */
    function getBlockHeight(bytes32 digest) external view override returns (uint32) {
        return _headers[digest].height;
    }

    /**
     * @dev See {IRelay-getBlockHash}.
     */
    function getBlockHash(uint32 height) external view override returns (bytes32) {
        bytes32 digest = _chain[height];
        require(digest > 0, ERR_BLOCK_NOT_FOUND);
        return digest;
    }

    /**
     * @dev See {IRelay-getBestBlock}.
     */
    function getBestBlock() external view override returns (bytes32 digest, uint32 height) {
        return (_bestBlock, _bestHeight);
    }

    /**
     * @dev See {IRelay-getCurrentBlock}.
     */
    function getCurrentBlock() external view override returns (bytes32 digest, uint32 height) {
        return (_currBlock, _currHeight);
    }



    /**
     * @dev See {IRelay-verifyTx}.
     */
    function verifyTx(
        uint32 height,
        uint256 index,
        bytes32 txid,
        bytes calldata header,
        bytes calldata proof,
        uint256 requiredconfirmations,
        bytes memory relaydata,
        address ethAddress
    ) external onlyOwner override returns (bool) {
        // txid must be little endian
        require(txid != 0, ERR_INVALID_TXID);
        if (height - 1 + requiredconfirmations > _currHeight) {
            emit ConfirmationsData(msg.sender, relaydata, (_currHeight - (height - 1)));
        } else {
            require(
                height - 1 + requiredconfirmations <= _currHeight,
                ERR_CONFIRMS
            );
            require(_chain[height] == header.hash256(), ERR_BLOCK_NOT_FOUND);
            bytes32 root = header.extractMerkleRootLE().toBytes32();
            require(
                ValidateSPV.prove(
                    txid,
                    root,
                    proof,
                    index
                ),
                ERR_VERIFY_TX
            );
            bytes memory relayDataToBeSent = parseRelayData(relaydata, ethAddress, requiredconfirmations);
            emit Data(msg.sender, relayDataToBeSent);
        }
        return true;
    }

    function parseRelayData(bytes memory relaydata, address ethAddress, uint256 requiredconfirmations) internal returns (bytes memory relayDataToBeSent) {
        require(relaysMapped[relaydata] == 0, ERR_RELAY_MAPPED);
        (string memory txhex, string memory toaddress, string memory txid) = abi.decode(relaydata, (string, string, string));
        bytes memory btcTxHex = fromHex(txhex);
        bytes memory btcAddress = fromHex(toaddress);
        bytes memory btcTxId = fromHex(txid);
        decryptData(btcTxHex);
        uint256 amount = 0;
        for(uint256 i = 0; i < outs.length; i++) {
            if(compareStringsbyBytes(string(outs[i].script), string(btcAddress))) {
                amount = amount.add(outs[i].value);
                break;
            }
        }
        require(amount > 0, ERR_INVALID_AMOUNT);
        relaysMapped[relaydata] = uuid;
        relayDataToBeSent = abi.encode(ethAddress, amount, uuid, btcTxHex, btcAddress, btcTxId, requiredconfirmations);
        txsInformation[uuid].txhex = btcTxHex;
        txsInformation[uuid].toaddress = btcAddress;
        txsInformation[uuid].txid = btcTxId;
        txsInformation[uuid].amount = amount;
        txsInformation[uuid].ethAddress = ethAddress;
        txsInformation[uuid].uuid = uuid;
        txsInformation[uuid].transferred = false;
        pendingMints[ethAddress].push(uuid);
        uuid++;
    }

    function find(uint value, address ethAddress) internal view returns(uint, bool) {
        uint256 index;
        bool found = false;
        for (uint256 i = 0; i < pendingMints[ethAddress].length; i++) {
            if (pendingMints[ethAddress][i] == value) {
                index = i;
                found = true;
            }
        }
        return (index, found);
    }

    function removeByValue(uint value, address ethAddress) internal {
        (uint pendingMintIndex, bool found) = find(value, ethAddress);
        require(found == true, ERR_MINTID_NOT_FOUND);
        delete pendingMints[ethAddress][pendingMintIndex];
    }

    function removeByIndex(uint i, address ethAddress) internal {
        while (i<pendingMints[ethAddress].length-1) {
            pendingMints[ethAddress][i] = pendingMints[ethAddress][i+1];
            i++;
        }
    }

    /**
     * @dev See {IRelay-processMint}.
     */
    function processMint(uint id) external onlyOwner override returns (bool) {
        Txdata memory txData = txsInformation[id];
        removeByValue(id, txData.ethAddress);
        completedMints[txData.ethAddress].push(id);
        return true;
    }

    /**
     * @dev See {IRelay-processTx}.
     */
    function processTx(bytes memory btcAddress, uint256 id) external onlyOwner override returns (bool) {
        (string memory toaddress) = abi.decode(btcAddress, (string));
        bytes memory btcAddressHex = fromHex(toaddress);
        txsInformation[id].transferred = true;
        emit txProcessed(msg.sender, btcAddressHex);
        return true;
    }

    /**
     * @dev See {IRelay-getPendingMints}.
     */
    function getPendingMints(address ethAddress) external view override returns(uint[] memory) {
        uint count = 0;
        for(uint256 i = 0; i < pendingMints[ethAddress].length; i++) {
            if (pendingMints[ethAddress][i] > 0 ) {
                count++;
            }
        }
        uint[] memory pendingTxs = new uint[](count);
        uint index = 0;
        for(uint256 i = 0; i < pendingMints[ethAddress].length; i++) {
            if (pendingMints[ethAddress][i] > 0 ) {
                pendingTxs[index] = pendingMints[ethAddress][i];
                index++;
            }
        }
        return pendingTxs;
    }

    /**
     * @dev See {IRelay-getCompletedMints}.
     */
    function getCompletedMints(address ethAddress) external view override returns(uint[] memory) {
        return completedMints[ethAddress];
    }

    function getPendingTransactions(address ethAddress) external view returns(Txdata[] memory) {
        uint count = 0;
        for(uint256 i = 0; i < pendingMints[ethAddress].length; i++) {
            if (pendingMints[ethAddress][i] > 0 ) {
                count++;
            }
        }
        Txdata[] memory pendingTxs = new Txdata[](count);
        uint index = 0;
        for(uint256 i = 0; i < pendingMints[ethAddress].length; i++) {
            if (pendingMints[ethAddress][i] > 0 ) {
                pendingTxs[index] = txsInformation[pendingMints[ethAddress][i]];
                index++;
            }
        }
        return pendingTxs;
    }

    function getCompletedTransactions(address ethAddress) external view returns(Txdata[] memory) {
        Txdata[] memory completedTxs = new Txdata[](completedMints[ethAddress].length);
        for(uint256 i = 0; i < completedMints[ethAddress].length; i++) {
            completedTxs[i] = txsInformation[completedMints[ethAddress][i]];
        }
        return completedTxs;
    }

    function getTransactionById(uint id) external view returns(Txdata memory) {
        require(id > 0, ERR_MINTID_INVALID);
        return txsInformation[id];
    }
}
