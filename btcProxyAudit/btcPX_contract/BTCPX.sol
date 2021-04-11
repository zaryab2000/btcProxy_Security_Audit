// SPDX-License-Identifier: NO LICENSE

pragma solidity 0.7.6;

import "@openzeppelin/contracts/token/ERC20/ERC20Burnable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BTCpx is ERC20Burnable, Ownable {
    using SafeMath for uint256;
    
    address public predicate;
    //0.3%
    uint256 public burnFee = 30;
    //0.1%
    uint256 public mintFee = 10;
    uint256 public constant percentageDivider = 10000;

    struct DAOData {
        uint256 mintFee;
        uint256 burnFee;
        bool isDAO;
        string accountId;
    }

    //maps ether to tx data
    mapping (address => mapping(uint256 => uint256)) public ethData;
    //maps uuid with address
    mapping (uint256 => address) public userForUuid;
    //maps hash with address
    mapping (uint256 => uint256) public mintStatus;
    //dao users mapping
    mapping (address => DAOData) private daoUsers;

    event Withdrawn(bytes btcAddr, uint256 value);
    event Mint(address receiver, uint256 value, uint256 uuid);
    
    modifier onlyPredicate() {
        require(_msgSender() == predicate, "Unauthorized");
        _;
    }

    constructor(address _predicate) ERC20("BTCpx", "Bitcoin Proxy") {
        predicate = _predicate;
        _setupDecimals(8);
    }

    /**
     * @dev Set the relay data
     *
     */
    function setData(bytes calldata _relayData) public onlyPredicate {
        (address _userAddr, uint256 _amount, uint256 _uuid) = abi.decode(_relayData, (address, uint256, uint256));
        userForUuid[_uuid] = _userAddr;
        mintStatus[_uuid] = 1;
        ethData[_userAddr][_uuid] = _amount;
    }

    /** 
     * @dev Set the dao users
     *
     */
    function setDAOUser(address _addr, uint256 _mintFee, uint256 _burnFee) public onlyOwner {
        daoUsers[_addr].isDAO = true;
        setDAOUserFees(_addr, _mintFee, _burnFee);
    }

    /** 
     * @dev Set the dao users
     *
     */
    function setDAOUserFees(address _addr, uint256 _mintFee, uint256 _burnFee) public onlyOwner {
        daoUsers[_addr].mintFee = _mintFee;
        daoUsers[_addr].burnFee = _burnFee;
    }

    /** 
     * @dev Set the dao users accunt id
     *
     */
    function setDAOUserAccountId(address _addr, string memory _accountId) public onlyOwner {
        daoUsers[_addr].accountId = _accountId;
    }

    /** 
     * @dev Set mint fee
     *
     */
    function setMintFee(uint256 fee) public onlyOwner {
        mintFee = fee;
    }

    /** 
     * @dev Set burn fee
     *
     */
    function setBurnFee(uint256 fee) public onlyOwner {
        burnFee = fee;
    }


    /**
     * @dev Destroys `amount` tokens of an account by owner.
     *
     * See {ERC20-_burn}.
     */
    function burn(address from, uint256 amount) public virtual onlyOwner {
        _burn(from, amount);
    }

    /**
     * @dev Destroys `amount` tokens from the caller.
     *
     * See {ERC20-_burn}.
     */
    function burn(bytes memory _btcAddr, uint256 _amount) public virtual {
        _burn(_msgSender(), _amount);
        uint256 _btcAmount = getWithdrawalBtcAmount(_msgSender(), _amount);
        emit Withdrawn(_btcAddr, _btcAmount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance.
     *
     * See {ERC20-_burn} and {ERC20-allowance}.
     *
     * Requirements: 
     *
     * - the caller must have allowance for `accounts's` tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount) public virtual override {
        uint256 decreasedAllowance = allowance(account, _msgSender()).sub(amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), decreasedAllowance);
        _burn(account, amount);
    }

    /** @dev Creates tokens based on btc amount and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements
     *
     * - `to` cannot be the zero address.
     */
    function mint(uint256 _uuid) public virtual {
        require(userForUuid[_uuid] == _msgSender(), "Unauthorized user");
        require(mintStatus[_uuid] == 1, "No pending mint");
        uint256 _amount = getMintBtcAmount(_msgSender(), ethData[_msgSender()][_uuid]);
        _mint(_msgSender(), _amount);
        mintStatus[_uuid] = 2;
        emit Mint(_msgSender(), _amount, _uuid);
    }
    
    /** 
     * @dev Creates `amount` tokens and ssigns them to `account`, increasing
     * the total supply only by the owner
     *
     */
    function mint(address addr, uint256 amount) public virtual onlyOwner {
        _mint(addr, amount);
    }

    // -----------------------------------------
    // Getter interface 
    // -----------------------------------------

    /**
     * @dev Check if user is dao or not
     *
     */
    function isDAOUser(address _addr) public view returns(bool) {
        return daoUsers[_addr].isDAO;
    }

    /**
     * @dev Get user mint fees
     *
     */
    function getUserMintFee(address _addr) public view returns(uint256) {
        if(isDAOUser(_addr)) {
            return daoUsers[_addr].mintFee;
        } else {
            return mintFee;
        }
    }

    /**
     * @dev Get user burn fees
     *
     */
    function getUserBurnFee(address _addr) public view returns(uint256) {
        if(isDAOUser(_addr)) {
            return daoUsers[_addr].burnFee;
        } else {
            return burnFee;
        }
    }

    /**
     * @dev Get dao user account id
     *
     */
    function getDAOUserAccountId(address _addr) public view returns(string memory) {
        return daoUsers[_addr].accountId;
    }

    /**
     * @dev Get amount of btc on redemption
     *
     */
    function getWithdrawalBtcAmount(address who, uint256 value) public view returns(uint256 amount) {
        return value.sub((value.mul(getUserBurnFee(who))).div(percentageDivider));
    }

    /**
     * @dev Get amount of btc on minting
     *
     */
    function getMintBtcAmount(address who, uint256 value) public view returns(uint256 amount) {
        return value.sub((value.mul(getUserMintFee(who))).div(percentageDivider));
    }

    /**
     * @dev check if btcpx is minted corrresponding to btc or not
     *
     */
    function getMintStatus(uint256 _uuid) public view returns(uint256) {
        return mintStatus[_uuid];
    }
    
    /**
     * @dev get eth address for hash
     *
     */
    function getEthAddress(uint256 _uuid) public view returns(address) {
        return userForUuid[_uuid];
    }

}