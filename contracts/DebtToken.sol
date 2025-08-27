// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "./Interfaces/IDebtToken.sol";
import "./Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "./Dependencies/OpenZeppelin/cryptography/ECDSA.sol";
import "./Dependencies/OpenZeppelin/math/SafeMath.sol";
import "./Dependencies/CheckContract.sol";

/**
 *
 * Based upon OpenZeppelin's ERC20 contract:
 * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol
 *
 * and their EIP2612 (ERC20Permit / ERC712) functionality:
 * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/53516bc555a454862470e7860a9b5254db4d00f5/contracts/token/ERC20/ERC20Permit.sol
 *
 *
 * --- Functionality added specific to the DebtToken ---
 *
 * 1) Transfer protection: blacklist of addresses that are invalid recipients (i.e. core contracts) in external
 * transfer() and transferFrom() calls. The purpose is to protect users from losing tokens by mistakenly sending token directly to a
 * core contract, when they should rather call the right function.
 *
 * 2) sendToPool() and returnFromPool(): functions callable only core contracts, which move Debt tokens between pool <-> user.
 */

contract DebtToken is OwnableUpgradeable, CheckContract, IDebtToken {
    using SafeMath for uint256;

    uint256 private _totalSupply;
    string internal constant _NAME = "USD for Filecoin Community";
    string internal constant _SYMBOL = "USDFC";
    string internal constant _VERSION = "1";
    uint8 internal constant _DECIMALS = 18;

    // --- Data for EIP2612 ---

    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant _PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _TYPE_HASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    // --- Data for EIP3009 ---

    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;
    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;
    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private _CACHED_DOMAIN_SEPARATOR;
    uint256 private _CACHED_CHAIN_ID;

    bytes32 private _HASHED_NAME;
    bytes32 private _HASHED_VERSION;

    // Nonces for EIP-2612
    mapping(address => uint256) private _nonces;

    // User data for Debt token
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // --- Addresses ---
    address public troveManagerAddress;
    address public stabilityPoolAddress;
    address public borrowerOperationsAddress;

    // EIP-3009 authorization states
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    constructor() initializer {}

    function initialize(
        address _troveManagerAddress,
        address _stabilityPoolAddress,
        address _borrowerOperationsAddress
    ) external initializer {
        __Ownable_init();
        _setAddresses(_troveManagerAddress, _stabilityPoolAddress, _borrowerOperationsAddress);
    }

    function _setAddresses(
        address _troveManagerAddress,
        address _stabilityPoolAddress,
        address _borrowerOperationsAddress
    ) private {
        checkContract(_troveManagerAddress);
        checkContract(_stabilityPoolAddress);
        checkContract(_borrowerOperationsAddress);

        troveManagerAddress = _troveManagerAddress;
        emit TroveManagerAddressChanged(_troveManagerAddress);

        stabilityPoolAddress = _stabilityPoolAddress;
        emit StabilityPoolAddressChanged(_stabilityPoolAddress);

        borrowerOperationsAddress = _borrowerOperationsAddress;
        emit BorrowerOperationsAddressChanged(_borrowerOperationsAddress);

        bytes32 hashedName = keccak256(bytes(_NAME));
        bytes32 hashedVersion = keccak256(bytes(_VERSION));

        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = _chainID();
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(_TYPE_HASH, hashedName, hashedVersion);
    }

    // --- Functions for intra-protocol calls ---

    function mint(address _account, uint256 _amount) external override {
        _requireCallerIsBorrowerOperations();
        _mint(_account, _amount);
    }

    function burn(address _account, uint256 _amount) external override {
        _requireCallerIsBOorTroveMorSP();
        _burn(_account, _amount);
    }

    function sendToPool(address _sender, address _poolAddress, uint256 _amount) external override {
        _requireCallerIsStabilityPool();
        _transfer(_sender, _poolAddress, _amount);
    }

    function returnFromPool(
        address _poolAddress,
        address _receiver,
        uint256 _amount
    ) external override {
        _requireCallerIsTroveMorSP();
        _transfer(_poolAddress, _receiver, _amount);
    }

    // --- External functions ---

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _account) external view override returns (uint256) {
        return _balances[_account];
    }

    function transfer(address _recipient, uint256 _amount) external override returns (bool) {
        _requireValidRecipient(_recipient);
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

    // --- EIP-712 Functionality ---

    function domainSeparator() public view override returns (bytes32) {
        if (_chainID() == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }

    /**
     * @dev Internal function to recover signer address from a signed message
     * @param _v Signature v component
     * @param _r Signature r component
     * @param _s Signature s component
     * @param _typeHashAndData The encoded type hash and data for signature verification
     * @return The recovered address
     */
    function _recover(
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        bytes memory _typeHashAndData
    ) internal view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), keccak256(_typeHashAndData))
        );
        return ECDSA.recover(digest, _v, _r, _s);
    }

    // --- EIP-2612 Functionality ---

    function permit(
        address _owner,
        address _spender,
        uint _amount,
        uint _deadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external override {
        require(_deadline >= block.timestamp, "EIP2612: expired deadline");
        uint256 currentNonce = _nonces[_owner];
        _nonces[_owner] = currentNonce + 1;
        address recoveredAddress = _recover(
            _v,
            _r,
            _s,
            abi.encode(_PERMIT_TYPEHASH, _owner, _spender, _amount, currentNonce, _deadline)
        );

        require(recoveredAddress == _owner, "EIP2612: invalid signature");
        _approve(_owner, _spender, _amount);
    }

    function nonces(address _owner) external view override returns (uint256) {
        return _nonces[_owner];
    }

    // --- EIP-3009 Functionality ---

    function transferWithAuthorization(
        address _from,
        address _to,
        uint256 _value,
        uint256 _validAfter,
        uint256 _validBefore,
        bytes32 _nonce,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external override {
        require(block.timestamp > _validAfter, "EIP3009: authorization not yet valid");
        require(block.timestamp < _validBefore, "EIP3009: authorization expired");
        require(!_authorizationStates[_from][_nonce], "EIP3009: authorization already used");
        _requireValidRecipient(_to);

        address recoveredAddress = _recover(
            _v,
            _r,
            _s,
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                _from,
                _to,
                _value,
                _validAfter,
                _validBefore,
                _nonce
            )
        );
        require(recoveredAddress == _from, "EIP3009: invalid signature");

        _authorizationStates[_from][_nonce] = true;
        emit AuthorizationUsed(_from, _nonce);

        _transfer(_from, _to, _value);
    }

    function receiveWithAuthorization(
        address _from,
        address _to,
        uint256 _value,
        uint256 _validAfter,
        uint256 _validBefore,
        bytes32 _nonce,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external override {
        require(_to == msg.sender, "EIP3009: caller must be the recipient");
        require(block.timestamp > _validAfter, "EIP3009: authorization not yet valid");
        require(block.timestamp < _validBefore, "EIP3009: authorization expired");
        require(!_authorizationStates[_from][_nonce], "EIP3009: authorization already used");
        _requireValidRecipient(_to);

        address recoveredAddress = _recover(
            _v,
            _r,
            _s,
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                _from,
                _to,
                _value,
                _validAfter,
                _validBefore,
                _nonce
            )
        );
        require(recoveredAddress == _from, "EIP3009: invalid signature");

        _authorizationStates[_from][_nonce] = true;
        emit AuthorizationUsed(_from, _nonce);

        _transfer(_from, _to, _value);
    }

    function cancelAuthorization(
        address _authorizer,
        bytes32 _nonce,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external override {
        require(!_authorizationStates[_authorizer][_nonce], "EIP3009: authorization already used");

        address recoveredAddress = _recover(
            _v,
            _r,
            _s,
            abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, _authorizer, _nonce)
        );
        require(recoveredAddress == _authorizer, "EIP3009: invalid signature");

        _authorizationStates[_authorizer][_nonce] = true;
        emit AuthorizationCanceled(_authorizer, _nonce);
    }

    function authorizationState(
        address _authorizer,
        bytes32 _nonce
    ) external view override returns (bool) {
        return _authorizationStates[_authorizer][_nonce];
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

    // --- Internal operations ---
    // Warning: sanity checks (for sender and recipient) should have been done before calling these internal functions

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

    function _burn(address _account, uint256 _amount) internal {
        require(_account != address(0), "ERC20: burn from the zero address");

        _balances[_account] = _balances[_account].sub(
            _amount,
            "ERC20: burn amount exceeds balance"
        );
        _totalSupply = _totalSupply.sub(_amount);
        emit Transfer(_account, address(0), _amount);
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
            "DebtToken: Cannot transfer tokens directly to the Debt token contract or the zero address"
        );
        require(
            _recipient != stabilityPoolAddress &&
                _recipient != troveManagerAddress &&
                _recipient != borrowerOperationsAddress,
            "DebtToken: Cannot transfer tokens directly to the StabilityPool, TroveManager or BorrowerOps"
        );
    }

    function _requireCallerIsBorrowerOperations() internal view {
        require(
            msg.sender == borrowerOperationsAddress,
            "DebtToken: Caller is not BorrowerOperations"
        );
    }

    function _requireCallerIsBOorTroveMorSP() internal view {
        require(
            msg.sender == borrowerOperationsAddress ||
                msg.sender == troveManagerAddress ||
                msg.sender == stabilityPoolAddress,
            "DebtToken: Caller is neither BorrowerOperations nor TroveManager nor StabilityPool"
        );
    }

    function _requireCallerIsStabilityPool() internal view {
        require(msg.sender == stabilityPoolAddress, "DebtToken: Caller is not the StabilityPool");
    }

    function _requireCallerIsTroveMorSP() internal view {
        require(
            msg.sender == troveManagerAddress || msg.sender == stabilityPoolAddress,
            "DebtToken: Caller is neither TroveManager nor StabilityPool"
        );
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
