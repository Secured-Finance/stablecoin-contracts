// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "./Interfaces/IBorrowerOperations.sol";
import "./Interfaces/ITroveManager.sol";
import "./Interfaces/IDebtToken.sol";
import "./Interfaces/ICollSurplusPool.sol";
import "./Interfaces/ISortedTroves.sol";
import "./Interfaces/IPriceFeed.sol";
import "./Interfaces/IProtocolTokenStaking.sol";
import "./Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "./Dependencies/OpenZeppelin/utils/ReentrancyGuardUpgradeable.sol";
import "./Dependencies/TroveBase.sol";

contract BorrowerOperations is
    TroveBase,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    IBorrowerOperations
{
    using SafeMath for uint;

    string public constant NAME = "BorrowerOperations";

    // --- Connected contract declarations ---

    ITroveManager public troveManager;
    address public stabilityPoolAddress;
    address public gasPoolAddress;
    ICollSurplusPool public collSurplusPool;
    IPriceFeed public priceFeed;
    IProtocolTokenStaking public protocolTokenStaking;
    address public protocolTokenStakingAddress;
    IDebtToken public debtToken;
    // A doubly linked list of Troves, sorted by their collateral ratios
    ISortedTroves public sortedTroves;

    // Track the last block number when action is performed on a trove
    mapping(address => uint256) public lastTroveActionBlock;

    /* --- Variable container structs  ---

    Used to hold, return and assign variables inside a function, in order to avoid the error:
    "CompilerError: Stack too deep". */

    struct LocalVariables_adjustTrove {
        uint price;
        uint collChange;
        uint netDebtChange;
        bool isCollIncrease;
        uint debt;
        uint coll;
        uint oldICR;
        uint newICR;
        uint newTCR;
        uint debtTokenFee;
        uint newDebt;
        uint newColl;
        uint stake;
    }

    struct LocalVariables_openTrove {
        uint price;
        uint debtTokenFee;
        uint netDebt;
        uint compositeDebt;
        uint ICR;
        uint NICR;
        uint stake;
        uint arrayIndex;
    }

    struct ContractsCache {
        ITroveManager troveManager;
        IActivePool activePool;
        IDebtToken debtToken;
    }

    // --- Functions ---

    constructor(
        uint _gasCompensation,
        uint _minNetDebt
    ) initializer TroveBase(_gasCompensation, _minNetDebt) {}

    // --- Dependency setters ---

    function initialize(
        address _troveManagerAddress,
        address _activePoolAddress,
        address _defaultPoolAddress,
        address _stabilityPoolAddress,
        address _gasPoolAddress,
        address _collSurplusPoolAddress,
        address _priceFeedAddress,
        address _sortedTrovesAddress,
        address _debtTokenAddress,
        address _protocolTokenStakingAddress
    ) external initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        __TroveBase_setAddresses(_activePoolAddress, _defaultPoolAddress);
        _setAddresses(
            _troveManagerAddress,
            _stabilityPoolAddress,
            _gasPoolAddress,
            _collSurplusPoolAddress,
            _priceFeedAddress,
            _sortedTrovesAddress,
            _debtTokenAddress,
            _protocolTokenStakingAddress
        );
    }

    function _setAddresses(
        address _troveManagerAddress,
        address _stabilityPoolAddress,
        address _gasPoolAddress,
        address _collSurplusPoolAddress,
        address _priceFeedAddress,
        address _sortedTrovesAddress,
        address _debtTokenAddress,
        address _protocolTokenStakingAddress
    ) private {
        // This makes impossible to open a trove with zero withdrawn debt token amount
        assert(MIN_NET_DEBT > 0);

        checkContract(_troveManagerAddress);
        checkContract(_stabilityPoolAddress);
        checkContract(_gasPoolAddress);
        checkContract(_collSurplusPoolAddress);
        checkContract(_priceFeedAddress);
        checkContract(_sortedTrovesAddress);
        checkContract(_debtTokenAddress);
        checkContract(_protocolTokenStakingAddress);

        _requireSameInitialParameters(_troveManagerAddress);

        troveManager = ITroveManager(_troveManagerAddress);
        stabilityPoolAddress = _stabilityPoolAddress;
        gasPoolAddress = _gasPoolAddress;
        collSurplusPool = ICollSurplusPool(_collSurplusPoolAddress);
        priceFeed = IPriceFeed(_priceFeedAddress);
        sortedTroves = ISortedTroves(_sortedTrovesAddress);
        debtToken = IDebtToken(_debtTokenAddress);
        protocolTokenStakingAddress = _protocolTokenStakingAddress;
        protocolTokenStaking = IProtocolTokenStaking(_protocolTokenStakingAddress);

        emit TroveManagerAddressChanged(_troveManagerAddress);
        emit StabilityPoolAddressChanged(_stabilityPoolAddress);
        emit GasPoolAddressChanged(_gasPoolAddress);
        emit CollSurplusPoolAddressChanged(_collSurplusPoolAddress);
        emit PriceFeedAddressChanged(_priceFeedAddress);
        emit SortedTrovesAddressChanged(_sortedTrovesAddress);
        emit DebtTokenAddressChanged(_debtTokenAddress);
        emit ProtocolTokenStakingAddressChanged(_protocolTokenStakingAddress);
    }

    // --- Borrower Trove Operations ---

    function openTrove(
        uint _maxFeePercentage,
        uint _debtTokenAmount,
        address _upperHint,
        address _lowerHint
    ) external payable override nonReentrant {
        _requireTroveActionNotInLatestBlock(msg.sender);
        lastTroveActionBlock[msg.sender] = block.number;

        _requireAmountGreaterThanZero(_debtTokenAmount);

        ContractsCache memory contractsCache = ContractsCache(troveManager, activePool, debtToken);
        LocalVariables_openTrove memory vars;

        vars.price = priceFeed.fetchPrice();
        bool isRecoveryMode = _checkRecoveryMode(vars.price);

        _requireValidMaxFeePercentage(_maxFeePercentage, isRecoveryMode);
        _requireTroveIsNotActive(contractsCache.troveManager, msg.sender);

        vars.debtTokenFee;
        vars.netDebt = _debtTokenAmount;

        if (!isRecoveryMode) {
            vars.debtTokenFee = _triggerBorrowingFee(
                contractsCache.troveManager,
                contractsCache.debtToken,
                _debtTokenAmount,
                _maxFeePercentage
            );
            vars.netDebt = vars.netDebt.add(vars.debtTokenFee);
        }
        _requireAtLeastMinNetDebt(vars.netDebt);

        // ICR is based on the composite debt, i.e. the requested debt token amount + borrowing fee + gas comp.
        vars.compositeDebt = _getCompositeDebt(vars.netDebt);
        assert(vars.compositeDebt > 0);

        vars.ICR = ProtocolMath._computeCR(msg.value, vars.compositeDebt, vars.price);
        vars.NICR = ProtocolMath._computeNominalCR(msg.value, vars.compositeDebt);

        if (isRecoveryMode) {
            _requireICRisAboveCCR(vars.ICR);
        } else {
            _requireICRisAboveMCR(vars.ICR);
            uint newTCR = _getNewTCRFromTroveChange(
                msg.value,
                true,
                vars.compositeDebt,
                true,
                vars.price
            ); // bools: coll increase, debt increase
            _requireNewTCRisAboveCCR(newTCR);
        }

        // Set the trove struct's properties
        contractsCache.troveManager.setTroveStatus(msg.sender, 1);
        contractsCache.troveManager.increaseTroveColl(msg.sender, msg.value);
        contractsCache.troveManager.increaseTroveDebt(msg.sender, vars.compositeDebt);

        contractsCache.troveManager.updateTroveRewardSnapshots(msg.sender);
        vars.stake = contractsCache.troveManager.updateStakeAndTotalStakes(msg.sender);

        sortedTroves.insert(msg.sender, vars.NICR, _upperHint, _lowerHint);
        vars.arrayIndex = contractsCache.troveManager.addTroveOwnerToArray(msg.sender);
        emit TroveCreated(msg.sender, vars.arrayIndex);

        // Move the filecoin to the Active Pool, and mint the debtTokenAmount to the borrower
        _activePoolAddColl(contractsCache.activePool, msg.value);
        _withdrawDebtToken(
            contractsCache.activePool,
            contractsCache.debtToken,
            msg.sender,
            _debtTokenAmount,
            vars.netDebt
        );
        // Move the gas compensation to the Gas Pool
        _withdrawDebtToken(
            contractsCache.activePool,
            contractsCache.debtToken,
            gasPoolAddress,
            GAS_COMPENSATION,
            GAS_COMPENSATION
        );

        emit TroveUpdated(
            msg.sender,
            vars.compositeDebt,
            msg.value,
            vars.stake,
            BorrowerOperation.openTrove
        );
        emit DebtTokenBorrowingFeePaid(msg.sender, vars.debtTokenFee);
    }

    // Send FIL as collateral to a trove
    function addColl(
        address _upperHint,
        address _lowerHint
    ) external payable override nonReentrant {
        _adjustTrove(msg.sender, 0, 0, false, _upperHint, _lowerHint, 0);
    }

    // Send FIL as collateral to a trove. Called by only the Stability Pool.
    function moveFILGainToTrove(
        address _borrower,
        address _upperHint,
        address _lowerHint
    ) external payable override {
        _requireCallerIsStabilityPool();
        _adjustTrove(_borrower, 0, 0, false, _upperHint, _lowerHint, 0);
    }

    // Withdraw FIL collateral from a trove
    function withdrawColl(
        uint _collWithdrawal,
        address _upperHint,
        address _lowerHint
    ) external override nonReentrant {
        _adjustTrove(msg.sender, _collWithdrawal, 0, false, _upperHint, _lowerHint, 0);
    }

    // Withdraw debt tokens from a trove: mint new debt tokens to the owner, and increase the trove's debt accordingly
    function withdrawDebtToken(
        uint _maxFeePercentage,
        uint _debtTokenAmount,
        address _upperHint,
        address _lowerHint
    ) external override nonReentrant {
        _adjustTrove(
            msg.sender,
            0,
            _debtTokenAmount,
            true,
            _upperHint,
            _lowerHint,
            _maxFeePercentage
        );
    }

    // Repay debt tokens to a Trove: Burn the repaid debt tokens, and reduce the trove's debt accordingly
    function repayDebtToken(
        uint _debtTokenAmount,
        address _upperHint,
        address _lowerHint
    ) external override nonReentrant {
        _adjustTrove(msg.sender, 0, _debtTokenAmount, false, _upperHint, _lowerHint, 0);
    }

    function adjustTrove(
        uint _maxFeePercentage,
        uint _collWithdrawal,
        uint _debtTokenChange,
        bool _isDebtIncrease,
        address _upperHint,
        address _lowerHint
    ) external payable override nonReentrant {
        _adjustTrove(
            msg.sender,
            _collWithdrawal,
            _debtTokenChange,
            _isDebtIncrease,
            _upperHint,
            _lowerHint,
            _maxFeePercentage
        );
    }

    /*
     * _adjustTrove(): Alongside a debt change, this function can perform either a collateral top-up or a collateral withdrawal.
     *
     * It therefore expects either a positive msg.value, or a positive _collWithdrawal argument.
     *
     * If both are positive, it will revert.
     */
    function _adjustTrove(
        address _borrower,
        uint _collWithdrawal,
        uint _debtTokenChange,
        bool _isDebtIncrease,
        address _upperHint,
        address _lowerHint,
        uint _maxFeePercentage
    ) internal {
        _requireTroveActionNotInLatestBlock(_borrower);
        lastTroveActionBlock[_borrower] = block.number;

        ContractsCache memory contractsCache = ContractsCache(troveManager, activePool, debtToken);
        LocalVariables_adjustTrove memory vars;

        vars.price = priceFeed.fetchPrice();
        bool isRecoveryMode = _checkRecoveryMode(vars.price);

        if (_isDebtIncrease) {
            _requireValidMaxFeePercentage(_maxFeePercentage, isRecoveryMode);
            _requireNonZeroDebtChange(_debtTokenChange);
        }
        _requireSingularCollChange(_collWithdrawal);
        _requireNonZeroAdjustment(_collWithdrawal, _debtTokenChange);
        _requireTroveIsActive(contractsCache.troveManager, _borrower);

        // Confirm the operation is either a borrower adjusting their own trove, or a pure FIL transfer from the Stability Pool to a trove
        assert(
            msg.sender == _borrower ||
                (msg.sender == stabilityPoolAddress && msg.value > 0 && _debtTokenChange == 0)
        );

        contractsCache.troveManager.applyPendingRewards(_borrower);

        // Get the collChange based on whether or not FIL was sent in the transaction
        (vars.collChange, vars.isCollIncrease) = _getCollChange(msg.value, _collWithdrawal);

        vars.netDebtChange = _debtTokenChange;

        // If the adjustment incorporates a debt increase and system is in Normal Mode, then trigger a borrowing fee
        if (_isDebtIncrease && !isRecoveryMode) {
            vars.debtTokenFee = _triggerBorrowingFee(
                contractsCache.troveManager,
                contractsCache.debtToken,
                _debtTokenChange,
                _maxFeePercentage
            );
            vars.netDebtChange = vars.netDebtChange.add(vars.debtTokenFee); // The raw debt change includes the fee
        }

        vars.debt = contractsCache.troveManager.getTroveDebt(_borrower);
        vars.coll = contractsCache.troveManager.getTroveColl(_borrower);

        // Get the trove's old ICR before the adjustment, and what its new ICR will be after the adjustment
        vars.oldICR = ProtocolMath._computeCR(vars.coll, vars.debt, vars.price);
        vars.newICR = _getNewICRFromTroveChange(
            vars.coll,
            vars.debt,
            vars.collChange,
            vars.isCollIncrease,
            vars.netDebtChange,
            _isDebtIncrease,
            vars.price
        );
        assert(_collWithdrawal <= vars.coll);

        // Check the adjustment satisfies all conditions for the current system mode
        _requireValidAdjustmentInCurrentMode(
            isRecoveryMode,
            _collWithdrawal,
            _isDebtIncrease,
            vars
        );

        // When the adjustment is a debt repayment, check it's a valid amount and that the caller has enough debt tokens
        if (!_isDebtIncrease && _debtTokenChange > 0) {
            _requireAtLeastMinNetDebt(_getNetDebt(vars.debt).sub(vars.netDebtChange));
            _requireValidDebtRepayment(vars.debt, vars.netDebtChange);
            _requireSufficientDebtTokenBalance(
                contractsCache.debtToken,
                _borrower,
                vars.netDebtChange
            );
        }

        (vars.newColl, vars.newDebt) = _updateTroveFromAdjustment(
            contractsCache.troveManager,
            _borrower,
            vars.collChange,
            vars.isCollIncrease,
            vars.netDebtChange,
            _isDebtIncrease
        );
        vars.stake = contractsCache.troveManager.updateStakeAndTotalStakes(_borrower);

        // Re-insert trove in to the sorted list
        uint newNICR = _getNewNominalICRFromTroveChange(
            vars.coll,
            vars.debt,
            vars.collChange,
            vars.isCollIncrease,
            vars.netDebtChange,
            _isDebtIncrease
        );
        sortedTroves.reInsert(_borrower, newNICR, _upperHint, _lowerHint);

        emit TroveUpdated(
            _borrower,
            vars.newDebt,
            vars.newColl,
            vars.stake,
            BorrowerOperation.adjustTrove
        );
        emit DebtTokenBorrowingFeePaid(msg.sender, vars.debtTokenFee);

        // Use the unmodified _debtTokenChange here, as we don't send the fee to the user
        _moveTokensAndFILfromAdjustment(
            contractsCache.activePool,
            contractsCache.debtToken,
            msg.sender,
            vars.collChange,
            vars.isCollIncrease,
            _debtTokenChange,
            _isDebtIncrease,
            vars.netDebtChange
        );
    }

    function closeTrove() external override nonReentrant {
        _requireTroveActionNotInLatestBlock(msg.sender);
        lastTroveActionBlock[msg.sender] = block.number;

        ITroveManager troveManagerCached = troveManager;
        IActivePool activePoolCached = activePool;
        IDebtToken debtTokenCached = debtToken;

        _requireTroveIsActive(troveManagerCached, msg.sender);
        uint price = priceFeed.fetchPrice();
        _requireNotInRecoveryMode(price);

        troveManagerCached.applyPendingRewards(msg.sender);

        uint coll = troveManagerCached.getTroveColl(msg.sender);
        uint debt = troveManagerCached.getTroveDebt(msg.sender);

        _requireSufficientDebtTokenBalance(debtTokenCached, msg.sender, debt.sub(GAS_COMPENSATION));

        uint newTCR = _getNewTCRFromTroveChange(coll, false, debt, false, price);
        _requireNewTCRisAboveCCR(newTCR);

        troveManagerCached.removeStake(msg.sender);
        troveManagerCached.closeTrove(msg.sender);

        emit TroveUpdated(msg.sender, 0, 0, 0, BorrowerOperation.closeTrove);

        // Burn the repaid debt tokens from the user's balance and the gas compensation from the Gas Pool
        _repayDebtToken(activePoolCached, debtTokenCached, msg.sender, debt.sub(GAS_COMPENSATION));
        _repayDebtToken(activePoolCached, debtTokenCached, gasPoolAddress, GAS_COMPENSATION);

        // Send the collateral back to the user
        activePoolCached.sendFIL(msg.sender, coll);
    }

    /**
     * Claim remaining collateral from a redemption or from a liquidation with ICR > MCR in Recovery Mode
     */
    function claimCollateral() external override {
        // send FIL from CollSurplus Pool to owner
        collSurplusPool.claimColl(msg.sender);
    }

    // --- Helper functions ---

    function _triggerBorrowingFee(
        ITroveManager _troveManager,
        IDebtToken _debtToken,
        uint _debtTokenAmount,
        uint _maxFeePercentage
    ) internal returns (uint) {
        _troveManager.decayBaseRateFromBorrowing(); // decay the baseRate state variable
        uint debtTokenFee = _troveManager.getBorrowingFee(_debtTokenAmount);

        _requireUserAcceptsFee(debtTokenFee, _debtTokenAmount, _maxFeePercentage);

        // Send fee to ProtocolTokenStaking contract
        protocolTokenStaking.increaseF_DebtToken(debtTokenFee);
        _debtToken.mint(protocolTokenStakingAddress, debtTokenFee);

        return debtTokenFee;
    }

    function _getUSDValue(uint _coll, uint _price) internal pure returns (uint) {
        uint usdValue = _price.mul(_coll).div(DECIMAL_PRECISION);

        return usdValue;
    }

    function _getCollChange(
        uint _collReceived,
        uint _requestedCollWithdrawal
    ) internal pure returns (uint collChange, bool isCollIncrease) {
        if (_collReceived != 0) {
            collChange = _collReceived;
            isCollIncrease = true;
        } else {
            collChange = _requestedCollWithdrawal;
        }
    }

    // Update trove's coll and debt based on whether they increase or decrease
    function _updateTroveFromAdjustment(
        ITroveManager _troveManager,
        address _borrower,
        uint _collChange,
        bool _isCollIncrease,
        uint _debtChange,
        bool _isDebtIncrease
    ) internal returns (uint, uint) {
        uint newColl = (_isCollIncrease)
            ? _troveManager.increaseTroveColl(_borrower, _collChange)
            : _troveManager.decreaseTroveColl(_borrower, _collChange);
        uint newDebt = (_isDebtIncrease)
            ? _troveManager.increaseTroveDebt(_borrower, _debtChange)
            : _troveManager.decreaseTroveDebt(_borrower, _debtChange);

        return (newColl, newDebt);
    }

    function _moveTokensAndFILfromAdjustment(
        IActivePool _activePool,
        IDebtToken _debtToken,
        address _borrower,
        uint _collChange,
        bool _isCollIncrease,
        uint _debtTokenChange,
        bool _isDebtIncrease,
        uint _netDebtChange
    ) internal {
        if (_isDebtIncrease) {
            _withdrawDebtToken(
                _activePool,
                _debtToken,
                _borrower,
                _debtTokenChange,
                _netDebtChange
            );
        } else {
            _repayDebtToken(_activePool, _debtToken, _borrower, _debtTokenChange);
        }

        if (_isCollIncrease) {
            _activePoolAddColl(_activePool, _collChange);
        } else {
            _activePool.sendFIL(_borrower, _collChange);
        }
    }

    // Send FIL to Active Pool and increase its recorded FIL balance
    function _activePoolAddColl(IActivePool _activePool, uint _amount) internal {
        (bool success, ) = address(_activePool).call{value: _amount}("");
        require(success, "BorrowerOps: Sending FIL to ActivePool failed");
    }

    // Issue the specified amount of debt token to _account and increases the total active debt (_netDebtIncrease potentially includes a debtTokenFee)
    function _withdrawDebtToken(
        IActivePool _activePool,
        IDebtToken _debtToken,
        address _account,
        uint _debtTokenAmount,
        uint _netDebtIncrease
    ) internal {
        _activePool.increaseDebt(_netDebtIncrease);
        _debtToken.mint(_account, _debtTokenAmount);
    }

    // Burn the specified amount of debt token from _account and decreases the total active debt
    function _repayDebtToken(
        IActivePool _activePool,
        IDebtToken _debtToken,
        address _account,
        uint _debtTokenAmount
    ) internal {
        _activePool.decreaseDebt(_debtTokenAmount);
        _debtToken.burn(_account, _debtTokenAmount);
    }

    // --- 'Require' wrapper functions ---

    function _requireAmountGreaterThanZero(uint _amount) internal pure {
        require(_amount != 0, "BorrowerOps: Amount must be greater than zero");
    }

    function _requireSingularCollChange(uint _collWithdrawal) internal view {
        require(
            msg.value == 0 || _collWithdrawal == 0,
            "BorrowerOps: Cannot withdraw and add coll"
        );
    }

    function _requireCallerIsBorrower(address _borrower) internal view {
        require(
            msg.sender == _borrower,
            "BorrowerOps: Caller must be the borrower for a withdrawal"
        );
    }

    function _requireNonZeroAdjustment(uint _collWithdrawal, uint _debtTokenChange) internal view {
        require(
            msg.value != 0 || _collWithdrawal != 0 || _debtTokenChange != 0,
            "BorrowerOps: There must be either a collateral change or a debt change"
        );
    }

    function _requireTroveIsActive(ITroveManager _troveManager, address _borrower) internal view {
        uint status = _troveManager.getTroveStatus(_borrower);
        require(status == 1, "BorrowerOps: Trove does not exist or is closed");
    }

    function _requireTroveIsNotActive(
        ITroveManager _troveManager,
        address _borrower
    ) internal view {
        uint status = _troveManager.getTroveStatus(_borrower);
        require(status != 1, "BorrowerOps: Trove is active");
    }

    function _requireNonZeroDebtChange(uint _debtTokenChange) internal pure {
        require(_debtTokenChange > 0, "BorrowerOps: Debt increase requires non-zero debtChange");
    }

    function _requireNotInRecoveryMode(uint _price) internal view {
        require(
            !_checkRecoveryMode(_price),
            "BorrowerOps: Operation not permitted during Recovery Mode"
        );
    }

    function _requireNoCollWithdrawal(uint _collWithdrawal) internal pure {
        require(
            _collWithdrawal == 0,
            "BorrowerOps: Collateral withdrawal not permitted Recovery Mode"
        );
    }

    function _requireValidAdjustmentInCurrentMode(
        bool _isRecoveryMode,
        uint _collWithdrawal,
        bool _isDebtIncrease,
        LocalVariables_adjustTrove memory _vars
    ) internal view {
        /*
         *In Recovery Mode, only allow:
         *
         * - Pure collateral top-up
         * - Pure debt repayment
         * - Collateral top-up with debt repayment
         * - A debt increase combined with a collateral top-up which makes the ICR >= 150% and improves the ICR (and by extension improves the TCR).
         *
         * In Normal Mode, ensure:
         *
         * - The new ICR is above MCR
         * - The adjustment won't pull the TCR below CCR
         */
        if (_isRecoveryMode) {
            _requireNoCollWithdrawal(_collWithdrawal);
            if (_isDebtIncrease) {
                _requireICRisAboveCCR(_vars.newICR);
                _requireNewICRisAboveOldICR(_vars.newICR, _vars.oldICR);
            }
        } else {
            // if Normal Mode
            _requireICRisAboveMCR(_vars.newICR);
            _vars.newTCR = _getNewTCRFromTroveChange(
                _vars.collChange,
                _vars.isCollIncrease,
                _vars.netDebtChange,
                _isDebtIncrease,
                _vars.price
            );
            _requireNewTCRisAboveCCR(_vars.newTCR);
        }
    }

    function _requireICRisAboveMCR(uint _newICR) internal pure {
        require(
            _newICR >= MCR,
            "BorrowerOps: An operation that would result in ICR < MCR is not permitted"
        );
    }

    function _requireICRisAboveCCR(uint _newICR) internal pure {
        require(_newICR >= CCR, "BorrowerOps: Operation must leave trove with ICR >= CCR");
    }

    function _requireNewICRisAboveOldICR(uint _newICR, uint _oldICR) internal pure {
        require(
            _newICR >= _oldICR,
            "BorrowerOps: Cannot decrease your Trove's ICR in Recovery Mode"
        );
    }

    function _requireNewTCRisAboveCCR(uint _newTCR) internal pure {
        require(
            _newTCR >= CCR,
            "BorrowerOps: An operation that would result in TCR < CCR is not permitted"
        );
    }

    function _requireAtLeastMinNetDebt(uint _netDebt) internal view {
        require(
            _netDebt >= MIN_NET_DEBT,
            "BorrowerOps: Trove's net debt must be greater than minimum"
        );
    }

    function _requireValidDebtRepayment(uint _currentDebt, uint _debtRepayment) internal view {
        require(
            _debtRepayment <= _currentDebt.sub(GAS_COMPENSATION),
            "BorrowerOps: Amount repaid must not be larger than the Trove's debt"
        );
    }

    function _requireCallerIsStabilityPool() internal view {
        require(msg.sender == stabilityPoolAddress, "BorrowerOps: Caller is not Stability Pool");
    }

    function _requireSufficientDebtTokenBalance(
        IDebtToken _debtToken,
        address _borrower,
        uint _debtRepayment
    ) internal view {
        require(
            _debtToken.balanceOf(_borrower) >= _debtRepayment,
            "BorrowerOps: Caller doesnt have enough tokens to make repayment"
        );
    }

    function _requireValidMaxFeePercentage(
        uint _maxFeePercentage,
        bool _isRecoveryMode
    ) internal pure {
        if (_isRecoveryMode) {
            require(
                _maxFeePercentage <= DECIMAL_PRECISION,
                "Max fee percentage must less than or equal to 100%"
            );
        } else {
            require(
                _maxFeePercentage >= BORROWING_FEE_FLOOR && _maxFeePercentage <= DECIMAL_PRECISION,
                "Max fee percentage must be between 0.5% and 100%"
            );
        }
    }

    function _requireTroveActionNotInLatestBlock(address _borrower) internal view {
        require(
            lastTroveActionBlock[_borrower] != block.number,
            "BorrowerOps: Trove action already performed in the latest block"
        );
    }

    // --- ICR and TCR getters ---

    // Compute the new collateral ratio, considering the change in coll and debt. Assumes 0 pending rewards.
    function _getNewNominalICRFromTroveChange(
        uint _coll,
        uint _debt,
        uint _collChange,
        bool _isCollIncrease,
        uint _debtChange,
        bool _isDebtIncrease
    ) internal pure returns (uint) {
        (uint newColl, uint newDebt) = _getNewTroveAmounts(
            _coll,
            _debt,
            _collChange,
            _isCollIncrease,
            _debtChange,
            _isDebtIncrease
        );

        uint newNICR = ProtocolMath._computeNominalCR(newColl, newDebt);
        return newNICR;
    }

    // Compute the new collateral ratio, considering the change in coll and debt. Assumes 0 pending rewards.
    function _getNewICRFromTroveChange(
        uint _coll,
        uint _debt,
        uint _collChange,
        bool _isCollIncrease,
        uint _debtChange,
        bool _isDebtIncrease,
        uint _price
    ) internal pure returns (uint) {
        (uint newColl, uint newDebt) = _getNewTroveAmounts(
            _coll,
            _debt,
            _collChange,
            _isCollIncrease,
            _debtChange,
            _isDebtIncrease
        );

        uint newICR = ProtocolMath._computeCR(newColl, newDebt, _price);
        return newICR;
    }

    function _getNewTroveAmounts(
        uint _coll,
        uint _debt,
        uint _collChange,
        bool _isCollIncrease,
        uint _debtChange,
        bool _isDebtIncrease
    ) internal pure returns (uint, uint) {
        uint newColl = _coll;
        uint newDebt = _debt;

        newColl = _isCollIncrease ? _coll.add(_collChange) : _coll.sub(_collChange);
        newDebt = _isDebtIncrease ? _debt.add(_debtChange) : _debt.sub(_debtChange);

        return (newColl, newDebt);
    }

    function _getNewTCRFromTroveChange(
        uint _collChange,
        bool _isCollIncrease,
        uint _debtChange,
        bool _isDebtIncrease,
        uint _price
    ) internal view returns (uint) {
        uint totalColl = getEntireSystemColl();
        uint totalDebt = getEntireSystemDebt();

        totalColl = _isCollIncrease ? totalColl.add(_collChange) : totalColl.sub(_collChange);
        totalDebt = _isDebtIncrease ? totalDebt.add(_debtChange) : totalDebt.sub(_debtChange);

        uint newTCR = ProtocolMath._computeCR(totalColl, totalDebt, _price);
        return newTCR;
    }

    function getCompositeDebt(uint _debt) external view override returns (uint) {
        return _getCompositeDebt(_debt);
    }
}
