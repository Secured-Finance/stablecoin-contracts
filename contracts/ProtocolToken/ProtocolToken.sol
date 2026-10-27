// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "../Dependencies/OpenZeppelin/cryptography/ECDSA.sol";
import "../Dependencies/OpenZeppelin/math/SafeMath.sol";
import "../Dependencies/CheckContract.sol";
import "../Interfaces/IProtocolToken.sol";

/*
 * Based upon OpenZeppelin's ERC20 contract:
 * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol
 *
 * and their EIP2612 (ERC20Permit / ERC712) functionality:
 * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/53516bc555a454862470e7860a9b5254db4d00f5/contracts/token/ERC20/ERC20Permit.sol
 *
 *
 *  --- Functionality added specific to the ProtocolToken ---
 *
 * 1) Transfer protection: blacklist of addresses that are invalid recipients (i.e. core contracts) in external
 * transfer() and transferFrom() calls. The purpose is to protect users from losing tokens by mistakenly sending ProtocolToken directly to a core contract,
 * when they should rather call the right function.
 *
 * 2) sendToProtocolTokenStaking(): callable only by core contracts, which move ProtocolToken tokens from user -> ProtocolTokenStaking contract.
 *
 */

contract ProtocolToken is OwnableUpgradeable, CheckContract, IProtocolToken {
    using SafeMath for uint256;

    // --- ERC20 Data ---

    string internal constant _NAME = "SFC";
    string internal constant _SYMBOL = "SFC";
    string internal constant _VERSION = "1";
    uint8 internal constant _DECIMALS = 18;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint private _totalSupply;

    // --- EIP 2612 Data ---

    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant _PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _TYPE_HASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private _CACHED_DOMAIN_SEPARATOR;
    uint256 private _CACHED_CHAIN_ID;

    bytes32 private _HASHED_NAME;
    bytes32 private _HASHED_VERSION;

    mapping(address => uint256) private _nonces;

    // --- ProtocolToken specific data ---

    uint public constant _100pct = 1000000000000000000; // 1e18 == 100%

    uint internal allocationStartTime;
    uint public annualAllocationRate;
    address public annualAllocationRecipient;
    // Status if annual allocation has been triggered for each year since deployment
    mapping(uint => bool) public allocationTriggered;

    address public protocolTokenStakingAddress;

    constructor() initializer {}

    // --- Functions ---

    function initialize(
        address _protocolTokenStakingAddress,
        address _annualAllocationRecipient,
        uint _annualAllocationRate
    ) external initializer {
        __Ownable_init();
        _setAddresses(_protocolTokenStakingAddress);
        _updateAnnualAllocationRecipient(_annualAllocationRecipient);
        _updateAnnualAllocationRate(_annualAllocationRate);
    }

    function _setAddresses(address _protocolTokenStakingAddress) private {
        checkContract(_protocolTokenStakingAddress);

        protocolTokenStakingAddress = _protocolTokenStakingAddress;

        bytes32 hashedName = keccak256(bytes(_NAME));
        bytes32 hashedVersion = keccak256(bytes(_VERSION));

        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = _chainID();
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(_TYPE_HASH, hashedName, hashedVersion);
    }

    // --- External functions ---

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _account) external view override returns (uint256) {
        return _balances[_account];
    }

    function getAllocationStartTime() external view override returns (uint256) {
        return allocationStartTime;
    }

    function transfer(address _recipient, uint256 _amount) external override returns (bool) {
        _requireValidRecipient(_recipient);

        // Otherwise, standard transfer functionality
        _transfer(msg.sender, _recipient, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) external view override returns (uint256) {
        return _allowances[_owner][_spender];
    }

    function approve(address _spender, uint256 _amount) external override returns (bool) {
        _approve(msg.sender, _spender, _amount);
        return true;
    }

    function transferFrom(
        address _sender,
        address _recipient,
        uint256 _amount
    ) external override returns (bool) {
        _requireValidRecipient(_recipient);

        _transfer(_sender, _recipient, _amount);
        _approve(
            _sender,
            msg.sender,
            _allowances[_sender][msg.sender].sub(
                _amount,
                "ERC20: transfer amount exceeds allowance"
            )
        );
        return true;
    }

    function sendToProtocolTokenStaking(address _sender, uint256 _amount) external override {
        _requireCallerIsProtocolTokenStaking();
        _transfer(_sender, protocolTokenStakingAddress, _amount);
    }

    // --- EIP 2612 functionality ---

    function domainSeparator() public view override returns (bytes32) {
        if (_chainID() == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }

    function permit(
        address _owner,
        address _spender,
        uint _amount,
        uint _deadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external override {
        require(_deadline >= block.timestamp, "ProtocolToken: expired deadline");
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        _PERMIT_TYPEHASH,
                        _owner,
                        _spender,
                        _amount,
                        _nonces[_owner]++,
                        _deadline
                    )
                )
            )
        );
        address recoveredAddress = ECDSA.recover(digest, _v, _r, _s);
        require(recoveredAddress == _owner, "ProtocolToken: invalid signature");
        _approve(_owner, _spender, _amount);
    }

    function nonces(address _owner) external view override returns (uint256) {
        // FOR EIP 2612
        return _nonces[_owner];
    }

    // --- ProtocolToken specific function ---

    function triggerInitialAllocation(
        address[] memory _accounts,
        uint256[] memory _amounts
    ) external onlyOwner {
        require(_totalSupply == 0, "ProtocolToken: already allocated");
        require(
            _accounts.length == _amounts.length,
            "ProtocolToken: accounts and amounts length mismatch"
        );

        allocationStartTime = block.timestamp;
        allocationTriggered[0] = true;

        for (uint i = 0; i < _accounts.length; i++) {
            _mint(_accounts[i], _amounts[i]);
        }
    }

    function triggerAnnualAllocation() external {
        require(_totalSupply != 0, "ProtocolToken: initial allocation has not been done yet");

        uint passedYears = (block.timestamp - allocationStartTime) / 365 days;
        require(
            !allocationTriggered[passedYears],
            "ProtocolToken: annual allocation is not yet available"
        );

        allocationTriggered[passedYears] = true;
        _mint(annualAllocationRecipient, _totalSupply.mul(annualAllocationRate).div(_100pct));
    }

    function updateAnnualAllocationRate(uint _annualAllocationRate) external onlyOwner {
        _updateAnnualAllocationRate(_annualAllocationRate);
    }

    function updateAnnualAllocationRecipient(
        address _annualAllocationRecipient
    ) external onlyOwner {
        _updateAnnualAllocationRecipient(_annualAllocationRecipient);
    }

    // --- Internal operations ---

    function _chainID() private pure returns (uint256 chainID) {
        assembly {
            chainID := chainid()
        }
    }

    function _buildDomainSeparator(
        bytes32 _typeHash,
        bytes32 _name,
        bytes32 _version
    ) private view returns (bytes32) {
        return keccak256(abi.encode(_typeHash, _name, _version, _chainID(), address(this)));
    }

    function _transfer(address _sender, address _recipient, uint256 _amount) internal {
        require(_sender != address(0), "ERC20: transfer from the zero address");
        require(_recipient != address(0), "ERC20: transfer to the zero address");

        _balances[_sender] = _balances[_sender].sub(
            _amount,
            "ERC20: transfer amount exceeds balance"
        );
        _balances[_recipient] = _balances[_recipient].add(_amount);
        emit Transfer(_sender, _recipient, _amount);
    }

    function _mint(address _account, uint256 _amount) internal {
        require(_account != address(0), "ERC20: mint to the zero address");

        _totalSupply = _totalSupply.add(_amount);
        _balances[_account] = _balances[_account].add(_amount);
        emit Transfer(address(0), _account, _amount);
    }

    function _approve(address _owner, address _spender, uint256 _amount) internal {
        require(_owner != address(0), "ERC20: approve from the zero address");
        require(_spender != address(0), "ERC20: approve to the zero address");

        _allowances[_owner][_spender] = _amount;
        emit Approval(_owner, _spender, _amount);
    }

    // --- 'require' functions ---

    function _requireValidRecipient(address _recipient) internal view {
        require(
            _recipient != address(0) && _recipient != address(this),
            "ProtocolToken: Cannot transfer tokens directly to the ProtocolToken token contract or the zero address"
        );
        require(
            _recipient != protocolTokenStakingAddress,
            "ProtocolToken: Cannot transfer tokens directly to the staking contract"
        );
    }

    function _requireCallerIsProtocolTokenStaking() internal view {
        require(
            msg.sender == protocolTokenStakingAddress,
            "ProtocolToken: caller must be the ProtocolTokenStaking contract"
        );
    }

    function _updateAnnualAllocationRate(uint _annualAllocationRate) internal {
        require(
            _annualAllocationRate <= _100pct,
            "ProtocolToken: annual allocation rate must be less than or equal to 100%"
        );

        annualAllocationRate = _annualAllocationRate;
        emit AnnualAllocationRateUpdated(_annualAllocationRate);
    }

    function _updateAnnualAllocationRecipient(address _annualAllocationRecipient) internal {
        annualAllocationRecipient = _annualAllocationRecipient;
        emit AnnualAllocationRecipientUpdated(_annualAllocationRecipient);
    }

    // --- Optional functions ---

    function name() external pure override returns (string memory) {
        return _NAME;
    }

    function symbol() external pure override returns (string memory) {
        return _SYMBOL;
    }

    function decimals() external pure override returns (uint8) {
        return _DECIMALS;
    }

    function version() external pure override returns (string memory) {
        return _VERSION;
    }

    function permitTypeHash() external pure override returns (bytes32) {
        return _PERMIT_TYPEHASH;
    }
}
