// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "./Interfaces/IBorrowerOperations.sol";
import "./Interfaces/IStabilityPool.sol";
import "./Interfaces/IBorrowerOperations.sol";
import "./Interfaces/ITroveManager.sol";
import "./Interfaces/IActivePool.sol";
import "./Interfaces/IDebtToken.sol";
import "./Interfaces/IPriceFeed.sol";
import "./Interfaces/ISortedTroves.sol";
import "./Interfaces/ICommunityIssuance.sol";
import "./Dependencies/OpenZeppelin/access/OwnableUpgradeable.sol";
import "./Dependencies/OpenZeppelin/utils/ReentrancyGuardUpgradeable.sol";
import "./Dependencies/OpenZeppelin/math/SafeMath.sol";
import "./Dependencies/ProtocolBase.sol";
import "./Dependencies/ProtocolSafeMath128.sol";
import "./Dependencies/CheckContract.sol";

/*
 * The Stability Pool holds debt tokens deposited by Stability Pool depositors.
 *
 * When a trove is liquidated, then depending on system conditions, some of its debt gets offset with
 * debt tokens in the Stability Pool:  that is, the offset debt evaporates, and an equal amount of debt tokens in the Stability Pool is burned.
 *
 * Thus, a liquidation causes each depositor to receive a debt token loss, in proportion to their deposit as a share of total deposits.
 * They also receive an FIL gain, as the FIL collateral of the liquidated trove is distributed among Stability depositors,
 * in the same proportion.
 *
 * When a liquidation occurs, it depletes every deposit by the same fraction: for example, a liquidation that depletes 40%
 * of the total debt token in the Stability Pool, depletes 40% of each deposit.
 *
 * A deposit that has experienced a series of liquidations is termed a "compounded deposit": each liquidation depletes the deposit,
 * multiplying it by some factor in range ]0,1[
 *
 *
 * --- IMPLEMENTATION ---
 *
 * We use a highly scalable method of tracking deposits and FIL gains that has O(1) complexity.
 *
 * When a liquidation occurs, rather than updating each depositor's deposit and FIL gain, we simply update two state variables:
 * a product P, and a sum S.
 *
 * A mathematical manipulation allows us to factor out the initial deposit, and accurately track all depositors' compounded deposits
 * and accumulated FIL gains over time, as liquidations occur, using just these two variables P and S. When depositors join the
 * Stability Pool, they get a snapshot of the latest P and S: P_t and S_t, respectively.
 *
 * The formula for a depositor's accumulated FIL gain is derived here:
 * https://github.com/liquity/dev/blob/main/papers/Scalable_Reward_Distribution_with_Compounding_Stakes.pdf
 *
 * For a given deposit d_t, the ratio P/P_t tells us the factor by which a deposit has decreased since it joined the Stability Pool,
 * and the term d_t * (S - S_t)/P_t gives us the deposit's total accumulated FIL gain.
 *
 * Each liquidation updates the product P and sum S. After a series of liquidations, a compounded deposit and corresponding FIL gain
 * can be calculated using the initial deposit, the depositor’s snapshots of P and S, and the latest values of P and S.
 *
 * Any time a depositor updates their deposit (withdrawal, top-up) their accumulated FIL gain is paid out, their new deposit is recorded
 * (based on their latest compounded deposit and modified by the withdrawal/top-up), and they receive new snapshots of the latest P and S.
 * Essentially, they make a fresh deposit that overwrites the old one.
 *
 *
 * --- SCALE FACTOR ---
 *
 * Since P is a running product in range ]0,1] that is always-decreasing, it should never reach 0 when multiplied by a number in range ]0,1[.
 * Unfortunately, Solidity floor division always reaches 0, sooner or later.
 *
 * A series of liquidations that nearly empty the Pool (and thus each multiply P by a very small number in range ]0,1[ ) may push P
 * to its 18 digit decimal limit, and round it to 0, when in fact the Pool hasn't been emptied: this would break deposit tracking.
 *
 * So, to track P accurately, we use a scale factor: if a liquidation would cause P to decrease to <1e-9 (and be rounded to 0 by Solidity),
 * we first multiply P by 1e9, and increment a currentScale factor by 1.
 *
 * The added benefit of using 1e9 for the scale factor (rather than 1e18) is that it ensures negligible precision loss close to the
 * scale boundary: when P is at its minimum value of 1e9, the relative precision loss in P due to floor division is only on the
 * order of 1e-9.
 *
 * --- EPOCHS ---
 *
 * Whenever a liquidation fully empties the Stability Pool, all deposits should become 0. However, setting P to 0 would make P be 0
 * forever, and break all future reward calculations.
 *
 * So, every time the Stability Pool is emptied by a liquidation, we reset P = 1 and currentScale = 0, and increment the currentEpoch by 1.
 *
 * --- TRACKING DEPOSIT OVER SCALE CHANGES AND EPOCHS ---
 *
 * When a deposit is made, it gets snapshots of the currentEpoch and the currentScale.
 *
 * When calculating a compounded deposit, we compare the current epoch to the deposit's epoch snapshot. If the current epoch is newer,
 * then the deposit was present during a pool-emptying liquidation, and necessarily has been depleted to 0.
 *
 * Otherwise, we then compare the current scale to the deposit's scale snapshot. If they're equal, the compounded deposit is given by d_t * P/P_t.
 * If it spans one scale change, it is given by d_t * P/(P_t * 1e9). If it spans more than one scale change, we define the compounded deposit
 * as 0, since it is now less than 1e-9'th of its initial value (e.g. a deposit of 1 billion USD has depleted to < 1 USD).
 *
 *
 *  --- TRACKING DEPOSITOR'S FIL GAIN OVER SCALE CHANGES AND EPOCHS ---
 *
 * In the current epoch, the latest value of S is stored upon each scale change, and the mapping (scale -> S) is stored for each epoch.
 *
 * This allows us to calculate a deposit's accumulated FIL gain, during the epoch in which the deposit was non-zero and earned FIL.
 *
 * We calculate the depositor's accumulated FIL gain for the scale at which they made the deposit, using the FIL gain formula:
 * e_1 = d_t * (S - S_t) / P_t
 *
 * and also for scale after, taking care to divide the latter by a factor of 1e9:
 * e_2 = d_t * S / (P_t * 1e9)
 *
 * The gain in the second scale will be full, as the starting point was in the previous scale, thus no need to subtract anything.
 * The deposit therefore was present for reward events from the beginning of that second scale.
 *
 *        S_i-S_t + S_{i+1}
 *      .<--------.------------>
 *      .         .
 *      . S_i     .   S_{i+1}
 *   <--.-------->.<----------->
 *   S_t.         .
 *   <->.         .
 *      t         .
 *  |---+---------|-------------|-----...
 *         i            i+1
 *
 * The sum of (e_1 + e_2) captures the depositor's total accumulated FIL gain, handling the case where their
 * deposit spanned one scale change. We only care about gains across one scale change, since the compounded
 * deposit is defined as being 0 once it has spanned more than one scale change.
 *
 *
 * --- UPDATING P WHEN A LIQUIDATION OCCURS ---
 *
 * Please see the implementation spec in the proof document, which closely follows on from the compounded deposit / FIL gain derivations:
 * https://github.com/liquity/liquity/blob/master/papers/Scalable_Reward_Distribution_with_Compounding_Stakes.pdf
 *
 *
 * --- ProtocolToken ISSUANCE TO STABILITY POOL DEPOSITORS ---
 *
 * An ProtocolToken issuance event occurs at every deposit operation, and every liquidation.
 *
 * Each deposit is tagged with the address of the front end through which it was made.
 *
 * All deposits earn a share of the issued ProtocolToken in proportion to the deposit as a share of total deposits. The ProtocolToken earned
 * by a given deposit, is split between the depositor and the front end through which the deposit was made, based on the front end's kickbackRate.
 *
 * Please see the system Readme for an overview:
 * https://github.com/liquity/dev/blob/main/README.md#lqty-issuance-to-stability-providers
 *
 * We use the same mathematical product-sum approach to track ProtocolToken gains for depositors, where 'G' is the sum corresponding to ProtocolToken gains.
 * The product P (and snapshot P_t) is re-used, as the ratio P/P_t tracks a deposit's depletion due to liquidations.
 *
 */
contract StabilityPool is
    ProtocolBase,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    CheckContract,
    IStabilityPool
{
    using ProtocolSafeMath128 for uint128;
    using SafeMath for uint;

    string public constant NAME = "StabilityPool";

    IBorrowerOperations public borrowerOperations;
    ITroveManager public troveManager;
    IActivePool public activePool;
    IDebtToken public debtToken;
    // Needed to check if there are pending liquidations
    ISortedTroves public sortedTroves;
    IPriceFeed public priceFeed;
    ICommunityIssuance public communityIssuance;

    uint256 internal FIL; // deposited filecoin tracker

    // Tracker for debt tokens held in the pool. Changes when users deposit/withdraw, and when Trove debt is offset.
    uint256 internal totalDebtTokenDeposits;

    // --- Data structures ---

    struct FrontEnd {
        uint kickbackRate;
        bool registered;
    }

    struct Deposit {
        uint initialValue;
        address frontEndTag;
    }

    struct Snapshots {
        uint S;
        uint P;
        uint G;
        uint128 scale;
        uint128 epoch;
    }

    mapping(address => Deposit) public deposits; // depositor address -> Deposit struct
    mapping(address => Snapshots) public depositSnapshots; // depositor address -> snapshots struct

    mapping(address => FrontEnd) public frontEnds; // front end address -> FrontEnd struct
    mapping(address => uint) public frontEndStakes; // front end address -> last recorded total deposits, tagged with that front end
    mapping(address => Snapshots) public frontEndSnapshots; // front end address -> snapshots struct

    /*  Product 'P': Running product by which to multiply an initial deposit, in order to find the current compounded deposit,
     * after a series of liquidations have occurred, each of which cancel some debt with the deposit.
     *
     * During its lifetime, a deposit's value evolves from d_t to d_t * P / P_t , where P_t
     * is the snapshot of P taken at the instant the deposit was made. 18-digit decimal.
     */
    uint public P;

    uint public constant SCALE_FACTOR = 1e9;

    // Each time the scale of P shifts by SCALE_FACTOR, the scale is incremented by 1
    uint128 public currentScale;

    // With each offset that fully empties the Pool, the epoch is incremented by 1
    uint128 public currentEpoch;

    /* FIL Gain sum 'S': During its lifetime, each deposit d_t earns an FIL gain of ( d_t * [S - S_t] )/P_t, where S_t
     * is the depositor's snapshot of S taken at the time t when the deposit was made.
     *
     * The 'S' sums are stored in a nested mapping (epoch => scale => sum):
     *
     * - The inner mapping records the sum S at different scales
     * - The outer mapping records the (scale => sum) mappings, for different epochs.
     */
    mapping(uint128 => mapping(uint128 => uint)) public epochToScaleToSum;

    /*
     * Similarly, the sum 'G' is used to calculate ProtocolToken gains. During it's lifetime, each deposit d_t earns a ProtocolToken gain of
     *  ( d_t * [G - G_t] )/P_t, where G_t is the depositor's snapshot of G taken at time t when  the deposit was made.
     *
     *  ProtocolToken reward events occur are triggered by depositor operations (new deposit, topup, withdrawal), and liquidations.
     *  In each case, the ProtocolToken reward is issued (i.e. G is updated), before other state changes are made.
     */
    mapping(uint128 => mapping(uint128 => uint)) public epochToScaleToG;

    // Error tracker for the error correction in the ProtocolToken issuance calculation
    uint public lastProtocolTokenError;
    // Error trackers for the error correction in the offset calculation
    uint public lastFILError_Offset;
    uint public lastDebtTokenLossError_Offset;

    // --- Functions ---

    constructor(
        uint _gasCompensation,
        uint _minNetDebt
    ) initializer ProtocolBase(_gasCompensation, _minNetDebt) {}

    // --- Contract setters ---

    function initialize(
        address _borrowerOperationsAddress,
        address _troveManagerAddress,
        address _activePoolAddress,
        address _debtTokenAddress,
        address _sortedTrovesAddress,
        address _priceFeedAddress,
        address _communityIssuanceAddress
    ) external initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        _setAddresses(
            _borrowerOperationsAddress,
            _troveManagerAddress,
            _activePoolAddress,
            _debtTokenAddress,
            _sortedTrovesAddress,
            _priceFeedAddress,
            _communityIssuanceAddress
        );
        P = DECIMAL_PRECISION;
    }

    function _setAddresses(
        address _borrowerOperationsAddress,
        address _troveManagerAddress,
        address _activePoolAddress,
        address _debtTokenAddress,
        address _sortedTrovesAddress,
        address _priceFeedAddress,
        address _communityIssuanceAddress
    ) private {
        checkContract(_borrowerOperationsAddress);
        checkContract(_troveManagerAddress);
        checkContract(_activePoolAddress);
        checkContract(_debtTokenAddress);
        checkContract(_sortedTrovesAddress);
        checkContract(_priceFeedAddress);
        checkContract(_communityIssuanceAddress);

        _requireSameInitialParameters(_troveManagerAddress);

        borrowerOperations = IBorrowerOperations(_borrowerOperationsAddress);
        troveManager = ITroveManager(_troveManagerAddress);
        activePool = IActivePool(_activePoolAddress);
        debtToken = IDebtToken(_debtTokenAddress);
        sortedTroves = ISortedTroves(_sortedTrovesAddress);
        priceFeed = IPriceFeed(_priceFeedAddress);
        communityIssuance = ICommunityIssuance(_communityIssuanceAddress);

        emit BorrowerOperationsAddressChanged(_borrowerOperationsAddress);
        emit TroveManagerAddressChanged(_troveManagerAddress);
        emit ActivePoolAddressChanged(_activePoolAddress);
        emit DebtTokenAddressChanged(_debtTokenAddress);
        emit SortedTrovesAddressChanged(_sortedTrovesAddress);
        emit PriceFeedAddressChanged(_priceFeedAddress);
        emit CommunityIssuanceAddressChanged(_communityIssuanceAddress);
    }

    // --- Getters for public variables. Required by IPool interface ---

    function getFIL() external view override returns (uint) {
        return FIL;
    }

    function getTotalDebtTokenDeposits() external view override returns (uint) {
        return totalDebtTokenDeposits;
    }

    // --- External Depositor Functions ---

    /*  provideToSP():
     *
     * - Triggers a ProtocolToken issuance, based on time passed since the last issuance. The ProtocolToken issuance is shared between *all* depositors and front ends
     * - Tags the deposit with the provided front end tag param, if it's a new deposit
     * - Sends depositor's accumulated gains (ProtocolToken, FIL) to depositor
     * - Sends the tagged front end's accumulated ProtocolToken gains to the tagged front end
     * - Increases deposit and tagged front end's stake, and takes new snapshots for each.
     */
    function provideToSP(uint _amount, address _frontEndTag) external override nonReentrant {
        _requireFrontEndIsRegisteredOrZero(_frontEndTag);
        _requireFrontEndNotRegistered(msg.sender);
        _requireNonZeroAmount(_amount);

        uint initialDeposit = deposits[msg.sender].initialValue;

        ICommunityIssuance communityIssuanceCached = communityIssuance;

        _triggerProtocolTokenIssuance(communityIssuanceCached);

        if (initialDeposit == 0) {
            _setFrontEndTag(msg.sender, _frontEndTag);
        }
        uint depositorFILGain = getDepositorFILGain(msg.sender);
        uint compoundedDebtTokenDeposit = getCompoundedDebtTokenDeposit(msg.sender);
        uint debtTokenLoss = initialDeposit.sub(compoundedDebtTokenDeposit); // Needed only for event log

        // First pay out any ProtocolToken gains
        address frontEnd = deposits[msg.sender].frontEndTag;
        _payOutProtocolTokenGains(communityIssuanceCached, msg.sender, frontEnd);

        // Update front end stake
        uint compoundedFrontEndStake = getCompoundedFrontEndStake(frontEnd);
        uint newFrontEndStake = compoundedFrontEndStake.add(_amount);
        _updateFrontEndStakeAndSnapshots(frontEnd, newFrontEndStake);
        emit FrontEndStakeChanged(frontEnd, newFrontEndStake, msg.sender);

        _sendDebtTokenToStabilityPool(msg.sender, _amount);

        uint newDeposit = compoundedDebtTokenDeposit.add(_amount);
        _updateDepositAndSnapshots(msg.sender, newDeposit);
        emit UserDepositChanged(msg.sender, newDeposit);

        emit FILGainWithdrawn(msg.sender, depositorFILGain, debtTokenLoss); // Debt Token Loss required for event log

        _sendFILGainToDepositor(depositorFILGain);
    }

    /*  withdrawFromSP():
     *
     * - Triggers a ProtocolToken issuance, based on time passed since the last issuance. The ProtocolToken issuance is shared between *all* depositors and front ends
     * - Removes the deposit's front end tag if it is a full withdrawal
     * - Sends all depositor's accumulated gains (ProtocolToken, FIL) to depositor
     * - Sends the tagged front end's accumulated ProtocolToken gains to the tagged front end
     * - Decreases deposit and tagged front end's stake, and takes new snapshots for each.
     *
     * If _amount > userDeposit, the user withdraws all of their compounded deposit.
     */
    function withdrawFromSP(uint _amount) external override nonReentrant {
        if (_amount != 0) {
            _requireNoUnderCollateralizedTroves();
        }
        uint initialDeposit = deposits[msg.sender].initialValue;
        _requireUserHasDeposit(initialDeposit);

        ICommunityIssuance communityIssuanceCached = communityIssuance;

        _triggerProtocolTokenIssuance(communityIssuanceCached);

        uint depositorFILGain = getDepositorFILGain(msg.sender);

        uint compoundedDebtTokenDeposit = getCompoundedDebtTokenDeposit(msg.sender);
        uint debtTokenToWithdraw = ProtocolMath._min(_amount, compoundedDebtTokenDeposit);
        uint debtTokenLoss = initialDeposit.sub(compoundedDebtTokenDeposit); // Needed only for event log

        // First pay out any ProtocolToken gains
        address frontEnd = deposits[msg.sender].frontEndTag;
        _payOutProtocolTokenGains(communityIssuanceCached, msg.sender, frontEnd);

        // Update front end stake
        uint compoundedFrontEndStake = getCompoundedFrontEndStake(frontEnd);
        uint newFrontEndStake = compoundedFrontEndStake.sub(debtTokenToWithdraw);
        _updateFrontEndStakeAndSnapshots(frontEnd, newFrontEndStake);
        emit FrontEndStakeChanged(frontEnd, newFrontEndStake, msg.sender);

        _sendDebtTokenToDepositor(msg.sender, debtTokenToWithdraw);

        // Update deposit
        uint newDeposit = compoundedDebtTokenDeposit.sub(debtTokenToWithdraw);
        _updateDepositAndSnapshots(msg.sender, newDeposit);
        emit UserDepositChanged(msg.sender, newDeposit);

        emit FILGainWithdrawn(msg.sender, depositorFILGain, debtTokenLoss); // Debt Token Loss required for event log

        _sendFILGainToDepositor(depositorFILGain);
    }

    /* withdrawFILGainToTrove:
     * - Triggers a ProtocolToken issuance, based on time passed since the last issuance. The ProtocolToken issuance is shared between *all* depositors and front ends
     * - Sends all depositor's ProtocolToken gain to  depositor
     * - Sends all tagged front end's ProtocolToken gain to the tagged front end
     * - Transfers the depositor's entire FIL gain from the Stability Pool to the caller's trove
     * - Leaves their compounded deposit in the Stability Pool
     * - Updates snapshots for deposit and tagged front end stake */
    function withdrawFILGainToTrove(
        address _upperHint,
        address _lowerHint
    ) external override nonReentrant {
        uint initialDeposit = deposits[msg.sender].initialValue;
        _requireUserHasDeposit(initialDeposit);
        _requireUserHasTrove(msg.sender);
        _requireUserHasFILGain(msg.sender);

        ICommunityIssuance communityIssuanceCached = communityIssuance;

        _triggerProtocolTokenIssuance(communityIssuanceCached);

        uint depositorFILGain = getDepositorFILGain(msg.sender);

        uint compoundedDebtTokenDeposit = getCompoundedDebtTokenDeposit(msg.sender);
        uint debtTokenLoss = initialDeposit.sub(compoundedDebtTokenDeposit); // Needed only for event log

        // First pay out any ProtocolToken gains
        address frontEnd = deposits[msg.sender].frontEndTag;
        _payOutProtocolTokenGains(communityIssuanceCached, msg.sender, frontEnd);

        // Update front end stake
        uint compoundedFrontEndStake = getCompoundedFrontEndStake(frontEnd);
        uint newFrontEndStake = compoundedFrontEndStake;
        _updateFrontEndStakeAndSnapshots(frontEnd, newFrontEndStake);
        emit FrontEndStakeChanged(frontEnd, newFrontEndStake, msg.sender);

        _updateDepositAndSnapshots(msg.sender, compoundedDebtTokenDeposit);

        /* Emit events before transferring FIL gain to Trove.
         This lets the event log make more sense (i.e. so it appears that first the FIL gain is withdrawn
        and then it is deposited into the Trove, not the other way around). */
        emit FILGainWithdrawn(msg.sender, depositorFILGain, debtTokenLoss);
        emit UserDepositChanged(msg.sender, compoundedDebtTokenDeposit);

        FIL = FIL.sub(depositorFILGain);
        emit StabilityPoolFILBalanceUpdated(FIL);
        emit FILSent(msg.sender, depositorFILGain);

        borrowerOperations.moveFILGainToTrove{value: depositorFILGain}(
            msg.sender,
            _upperHint,
            _lowerHint
        );
    }

    // --- ProtocolToken issuance functions ---

    function _triggerProtocolTokenIssuance(ICommunityIssuance _communityIssuance) internal {
        uint protocolTokenIssuance = _communityIssuance.issueProtocolToken();
        _updateG(protocolTokenIssuance);
    }

    function _updateG(uint _protocolTokenIssuance) internal {
        uint totalDebtToken = totalDebtTokenDeposits; // cached to save an SLOAD
        /*
         * When total deposits is 0, G is not updated. In this case, the ProtocolToken issued can not be obtained by later
         * depositors - it is missed out on, and remains in the balanceof the CommunityIssuance contract.
         *
         */
        if (totalDebtToken == 0 || _protocolTokenIssuance == 0) {
            return;
        }

        uint protocolTokenPerUnitStaked;
        protocolTokenPerUnitStaked = _computeProtocolTokenPerUnitStaked(
            _protocolTokenIssuance,
            totalDebtToken
        );

        uint marginalProtocolTokenGain = protocolTokenPerUnitStaked.mul(P);
        epochToScaleToG[currentEpoch][currentScale] = epochToScaleToG[currentEpoch][currentScale]
            .add(marginalProtocolTokenGain);

        emit G_Updated(epochToScaleToG[currentEpoch][currentScale], currentEpoch, currentScale);
    }

    function _computeProtocolTokenPerUnitStaked(
        uint _protocolTokenIssuance,
        uint _totalDebtTokenDeposits
    ) internal returns (uint) {
        /*
         * Calculate the ProtocolToken-per-unit staked.  Division uses a "feedback" error correction, to keep the
         * cumulative error low in the running total G:
         *
         * 1) Form a numerator which compensates for the floor division error that occurred the last time this
         * function was called.
         * 2) Calculate "per-unit-staked" ratio.
         * 3) Multiply the ratio back by its denominator, to reveal the current floor division error.
         * 4) Store this error for use in the next correction when this function is called.
         * 5) Note: static analysis tools complain about this "division before multiplication", however, it is intended.
         */
        uint protocolTokenNumerator = _protocolTokenIssuance.mul(DECIMAL_PRECISION).add(
            lastProtocolTokenError
        );

        uint protocolTokenPerUnitStaked = protocolTokenNumerator.div(_totalDebtTokenDeposits);
        lastProtocolTokenError = protocolTokenNumerator.sub(
            protocolTokenPerUnitStaked.mul(_totalDebtTokenDeposits)
        );

        return protocolTokenPerUnitStaked;
    }

    // --- Liquidation functions ---

    /*
     * Cancels out the specified debt against the debt token contained in the Stability Pool (as far as possible)
     * and transfers the Trove's FIL collateral from ActivePool to StabilityPool.
     * Only called by liquidation functions in the TroveManager.
     */
    function offset(uint _debtToOffset, uint _collToAdd) external override nonReentrant {
        _requireCallerIsTroveManager();
        uint totalDebtToken = totalDebtTokenDeposits; // cached to save an SLOAD
        if (totalDebtToken == 0 || _debtToOffset == 0) {
            return;
        }

        _triggerProtocolTokenIssuance(communityIssuance);

        (uint FILGainPerUnitStaked, uint debtTokenLossPerUnitStaked) = _computeRewardsPerUnitStaked(
            _collToAdd,
            _debtToOffset,
            totalDebtToken
        );

        _updateRewardSumAndProduct(FILGainPerUnitStaked, debtTokenLossPerUnitStaked); // updates S and P

        _moveOffsetCollAndDebt(_collToAdd, _debtToOffset);
    }

    // --- Offset helper functions ---

    function _computeRewardsPerUnitStaked(
        uint _collToAdd,
        uint _debtToOffset,
        uint _totalDebtTokenDeposits
    ) internal returns (uint FILGainPerUnitStaked, uint debtTokenLossPerUnitStaked) {
        /*
         * Compute the debt token and FIL rewards. Uses a "feedback" error correction, to keep
         * the cumulative error in the P and S state variables low:
         *
         * 1) Form numerators which compensate for the floor division errors that occurred the last time this
         * function was called.
         * 2) Calculate "per-unit-staked" ratios.
         * 3) Multiply each ratio back by its denominator, to reveal the current floor division error.
         * 4) Store these errors for use in the next correction when this function is called.
         * 5) Note: static analysis tools complain about this "division before multiplication", however, it is intended.
         */
        uint FILNumerator = _collToAdd.mul(DECIMAL_PRECISION).add(lastFILError_Offset);

        assert(_debtToOffset <= _totalDebtTokenDeposits);
        if (_debtToOffset == _totalDebtTokenDeposits) {
            debtTokenLossPerUnitStaked = DECIMAL_PRECISION; // When the Pool depletes to 0, so does each deposit
            lastDebtTokenLossError_Offset = 0;
        } else {
            uint debtTokenLossNumerator = _debtToOffset.mul(DECIMAL_PRECISION).sub(
                lastDebtTokenLossError_Offset
            );
            /*
             * Add 1 to make error in quotient positive. We want "slightly too much" debt token loss,
             * which ensures the error in any given compoundedDebtTokenDeposit favors the Stability Pool.
             */
            debtTokenLossPerUnitStaked = (debtTokenLossNumerator.div(_totalDebtTokenDeposits)).add(
                1
            );
            lastDebtTokenLossError_Offset = (
                debtTokenLossPerUnitStaked.mul(_totalDebtTokenDeposits)
            ).sub(debtTokenLossNumerator);
        }

        FILGainPerUnitStaked = FILNumerator.div(_totalDebtTokenDeposits);
        lastFILError_Offset = FILNumerator.sub(FILGainPerUnitStaked.mul(_totalDebtTokenDeposits));

        return (FILGainPerUnitStaked, debtTokenLossPerUnitStaked);
    }

    // Update the Stability Pool reward sum S and product P
    function _updateRewardSumAndProduct(
        uint _FILGainPerUnitStaked,
        uint _debtTokenLossPerUnitStaked
    ) internal {
        uint currentP = P;
        uint newP;

        assert(_debtTokenLossPerUnitStaked <= DECIMAL_PRECISION);
        /*
         * The newProductFactor is the factor by which to change all deposits, due to the depletion of Stability Pool debt tokens in the liquidation.
         * We make the product factor 0 if there was a pool-emptying. Otherwise, it is (1 - debtTokenLossPerUnitStaked)
         */
        uint newProductFactor = uint(DECIMAL_PRECISION).sub(_debtTokenLossPerUnitStaked);

        uint128 currentScaleCached = currentScale;
        uint128 currentEpochCached = currentEpoch;
        uint currentS = epochToScaleToSum[currentEpochCached][currentScaleCached];

        /*
         * Calculate the new S first, before we update P.
         * The FIL gain for any given depositor from a liquidation depends on the value of their deposit
         * (and the value of totalDeposits) prior to the Stability being depleted by the debt in the liquidation.
         *
         * Since S corresponds to FIL gain, and P to deposit loss, we update S first.
         */
        uint marginalFILGain = _FILGainPerUnitStaked.mul(currentP);
        uint newS = currentS.add(marginalFILGain);
        epochToScaleToSum[currentEpochCached][currentScaleCached] = newS;
        emit S_Updated(newS, currentEpochCached, currentScaleCached);

        // If the Stability Pool was emptied, increment the epoch, and reset the scale and product P
        if (newProductFactor == 0) {
            currentEpoch = currentEpochCached.add(1);
            emit EpochUpdated(currentEpoch);
            currentScale = 0;
            emit ScaleUpdated(currentScale);
            newP = DECIMAL_PRECISION;

            // If multiplying P by a non-zero product factor would reduce P below the scale boundary, increment the scale
        } else if (currentP.mul(newProductFactor).div(DECIMAL_PRECISION) < SCALE_FACTOR) {
            newP = currentP.mul(newProductFactor).mul(SCALE_FACTOR).div(DECIMAL_PRECISION);
            currentScaleCached = currentScaleCached.add(1);

            // A very high-fraction offset can require two scale changes to keep P above SCALE_FACTOR.
            // Recompute from the original operands to avoid compounding the first division's rounding loss.
            if (newP < SCALE_FACTOR) {
                newP = currentP.mul(newProductFactor).mul(SCALE_FACTOR ** 2).div(DECIMAL_PRECISION);
                currentScaleCached = currentScaleCached.add(1);
            }

            currentScale = currentScaleCached;
            emit ScaleUpdated(currentScaleCached);
        } else {
            newP = currentP.mul(newProductFactor).div(DECIMAL_PRECISION);
        }

        assert(newP > 0);
        P = newP;

        emit P_Updated(newP);
    }

    function _moveOffsetCollAndDebt(uint _collToAdd, uint _debtToOffset) internal {
        IActivePool activePoolCached = activePool;

        // Cancel the liquidated debt with the debt token in the stability pool
        activePoolCached.decreaseDebt(_debtToOffset);
        _decreaseDebtTokenDeposits(_debtToOffset);

        // Burn the debt that was successfully offset
        debtToken.burn(address(this), _debtToOffset);

        activePoolCached.sendFIL(address(this), _collToAdd);
    }

    function _decreaseDebtTokenDeposits(uint _amount) internal {
        uint newTotalDebtTokenDeposits = totalDebtTokenDeposits.sub(_amount);
        totalDebtTokenDeposits = newTotalDebtTokenDeposits;
        emit StabilityPoolDebtTokenBalanceUpdated(newTotalDebtTokenDeposits);
    }

    // --- Reward calculator functions for depositor and front end ---

    /* Calculates the FIL gain earned by the deposit since its last snapshots were taken.
     * Given by the formula:  E = d0 * (S - S(0))/P(0)
     * where S(0) and P(0) are the depositor's snapshots of the sum S and product P, respectively.
     * d0 is the last recorded deposit value.
     */
    function getDepositorFILGain(address _depositor) public view override returns (uint) {
        uint initialDeposit = deposits[_depositor].initialValue;

        if (initialDeposit == 0) {
            return 0;
        }

        Snapshots memory snapshots = depositSnapshots[_depositor];

        uint FILGain = _getFILGainFromSnapshots(initialDeposit, snapshots);
        return FILGain;
    }

    function _getFILGainFromSnapshots(
        uint initialDeposit,
        Snapshots memory snapshots
    ) internal view returns (uint) {
        /*
         * Grab the sum 'S' from the epoch at which the stake was made. The FIL gain may span up to one scale change.
         * If it does, the second portion of the FIL gain is scaled by 1e9.
         * If the gain spans no scale change, the second portion will be 0.
         */
        uint128 epochSnapshot = snapshots.epoch;
        uint128 scaleSnapshot = snapshots.scale;
        uint S_Snapshot = snapshots.S;
        uint P_Snapshot = snapshots.P;

        uint firstPortion = epochToScaleToSum[epochSnapshot][scaleSnapshot].sub(S_Snapshot);
        uint secondPortion = epochToScaleToSum[epochSnapshot][scaleSnapshot.add(1)].div(
            SCALE_FACTOR
        );

        uint FILGain = initialDeposit.mul(firstPortion.add(secondPortion)).div(P_Snapshot).div(
            DECIMAL_PRECISION
        );

        return FILGain;
    }

    /*
     * Calculate the ProtocolToken gain earned by a deposit since its last snapshots were taken.
     * Given by the formula:  ProtocolToken = d0 * (G - G(0))/P(0)
     * where G(0) and P(0) are the depositor's snapshots of the sum G and product P, respectively.
     * d0 is the last recorded deposit value.
     */
    function getDepositorProtocolTokenGain(address _depositor) public view override returns (uint) {
        uint initialDeposit = deposits[_depositor].initialValue;
        if (initialDeposit == 0) {
            return 0;
        }

        address frontEndTag = deposits[_depositor].frontEndTag;

        /*
         * If not tagged with a front end, the depositor gets a 100% cut of what their deposit earned.
         * Otherwise, their cut of the deposit's earnings is equal to the kickbackRate, set by the front end through
         * which they made their deposit.
         */
        uint kickbackRate = frontEndTag == address(0)
            ? DECIMAL_PRECISION
            : frontEnds[frontEndTag].kickbackRate;

        Snapshots memory snapshots = depositSnapshots[_depositor];

        uint protocolTokenGain = kickbackRate
            .mul(_getProtocolTokenGainFromSnapshots(initialDeposit, snapshots))
            .div(DECIMAL_PRECISION);

        return protocolTokenGain;
    }

    /*
     * Return the ProtocolToken gain earned by the front end. Given by the formula:  E = D0 * (G - G(0))/P(0)
     * where G(0) and P(0) are the depositor's snapshots of the sum G and product P, respectively.
     *
     * D0 is the last recorded value of the front end's total tagged deposits.
     */
    function getFrontEndProtocolTokenGain(address _frontEnd) public view override returns (uint) {
        uint frontEndStake = frontEndStakes[_frontEnd];
        if (frontEndStake == 0) {
            return 0;
        }

        uint kickbackRate = frontEnds[_frontEnd].kickbackRate;
        uint frontEndShare = uint(DECIMAL_PRECISION).sub(kickbackRate);

        Snapshots memory snapshots = frontEndSnapshots[_frontEnd];

        uint protocolTokenGain = frontEndShare
            .mul(_getProtocolTokenGainFromSnapshots(frontEndStake, snapshots))
            .div(DECIMAL_PRECISION);
        return protocolTokenGain;
    }

    function _getProtocolTokenGainFromSnapshots(
        uint initialStake,
        Snapshots memory snapshots
    ) internal view returns (uint) {
        /*
         * Grab the sum 'G' from the epoch at which the stake was made. The ProtocolToken gain may span up to one scale change.
         * If it does, the second portion of the ProtocolToken gain is scaled by 1e9.
         * If the gain spans no scale change, the second portion will be 0.
         */
        uint128 epochSnapshot = snapshots.epoch;
        uint128 scaleSnapshot = snapshots.scale;
        uint G_Snapshot = snapshots.G;
        uint P_Snapshot = snapshots.P;

        uint firstPortion = epochToScaleToG[epochSnapshot][scaleSnapshot].sub(G_Snapshot);
        uint secondPortion = epochToScaleToG[epochSnapshot][scaleSnapshot.add(1)].div(SCALE_FACTOR);

        uint protocolTokenGain = initialStake
            .mul(firstPortion.add(secondPortion))
            .div(P_Snapshot)
            .div(DECIMAL_PRECISION);

        return protocolTokenGain;
    }

    // --- Compounded deposit and compounded front end stake ---

    /*
     * Return the user's compounded deposit. Given by the formula:  d = d0 * P/P(0)
     * where P(0) is the depositor's snapshot of the product P, taken when they last updated their deposit.
     */
    function getCompoundedDebtTokenDeposit(address _depositor) public view override returns (uint) {
        uint initialDeposit = deposits[_depositor].initialValue;
        if (initialDeposit == 0) {
            return 0;
        }

        Snapshots memory snapshots = depositSnapshots[_depositor];

        uint compoundedDeposit = _getCompoundedStakeFromSnapshots(initialDeposit, snapshots);
        return compoundedDeposit;
    }

    /*
     * Return the front end's compounded stake. Given by the formula:  D = D0 * P/P(0)
     * where P(0) is the depositor's snapshot of the product P, taken at the last time
     * when one of the front end's tagged deposits updated their deposit.
     *
     * The front end's compounded stake is equal to the sum of its depositors' compounded deposits.
     */
    function getCompoundedFrontEndStake(address _frontEnd) public view override returns (uint) {
        uint frontEndStake = frontEndStakes[_frontEnd];
        if (frontEndStake == 0) {
            return 0;
        }

        Snapshots memory snapshots = frontEndSnapshots[_frontEnd];

        uint compoundedFrontEndStake = _getCompoundedStakeFromSnapshots(frontEndStake, snapshots);
        return compoundedFrontEndStake;
    }

    // Internal function, used to calculcate compounded deposits and compounded front end stakes.
    function _getCompoundedStakeFromSnapshots(
        uint initialStake,
        Snapshots memory snapshots
    ) internal view returns (uint) {
        uint snapshot_P = snapshots.P;
        uint128 scaleSnapshot = snapshots.scale;
        uint128 epochSnapshot = snapshots.epoch;

        // If stake was made before a pool-emptying event, then it has been fully cancelled with debt -- so, return 0
        if (epochSnapshot < currentEpoch) {
            return 0;
        }

        uint compoundedStake;
        uint128 scaleDiff = currentScale.sub(scaleSnapshot);

        /* Compute the compounded stake. If a scale change in P was made during the stake's lifetime,
         * account for it. If more than one scale change was made, then the stake has decreased by a factor of
         * at least 1e-9 -- so return 0.
         */
        if (scaleDiff == 0) {
            compoundedStake = initialStake.mul(P).div(snapshot_P);
        } else if (scaleDiff == 1) {
            compoundedStake = initialStake.mul(P).div(snapshot_P).div(SCALE_FACTOR);
        } else {
            // if scaleDiff >= 2
            compoundedStake = 0;
        }

        /*
         * If compounded deposit is less than a billionth of the initial deposit, return 0.
         *
         * NOTE: originally, this line was in place to stop rounding errors making the deposit too large. However, the error
         * corrections should ensure the error in P "favors the Pool", i.e. any given compounded deposit should slightly less
         * than it's theoretical value.
         *
         * Thus it's unclear whether this line is still really needed.
         */
        if (compoundedStake < initialStake.div(1e9)) {
            return 0;
        }

        return compoundedStake;
    }

    // --- Sender functions for debt token deposit, FIL gains and ProtocolToken gains ---

    // Transfer the debt tokens from the user to the Stability Pool's address, and update its recorded debt token deposit
    function _sendDebtTokenToStabilityPool(address _address, uint _amount) internal {
        debtToken.sendToPool(_address, address(this), _amount);
        uint newTotalDebtTokenDeposits = totalDebtTokenDeposits.add(_amount);
        totalDebtTokenDeposits = newTotalDebtTokenDeposits;
        emit StabilityPoolDebtTokenBalanceUpdated(newTotalDebtTokenDeposits);
    }

    function _sendFILGainToDepositor(uint _amount) internal {
        if (_amount == 0) {
            return;
        }
        uint newFIL = FIL.sub(_amount);
        FIL = newFIL;
        emit StabilityPoolFILBalanceUpdated(newFIL);
        emit FILSent(msg.sender, _amount);

        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "StabilityPool: sending FIL failed");
    }

    // Send debt tokens to user and decrease debt token deposits in Pool
    function _sendDebtTokenToDepositor(address _depositor, uint withdrawalAmount) internal {
        if (withdrawalAmount == 0) {
            return;
        }

        debtToken.returnFromPool(address(this), _depositor, withdrawalAmount);
        _decreaseDebtTokenDeposits(withdrawalAmount);
    }

    // --- External Front End functions ---

    // Front end makes a one-time selection of kickback rate upon registering
    function registerFrontEnd(uint _kickbackRate) external override {
        _requireFrontEndNotRegistered(msg.sender);
        _requireUserHasNoDeposit(msg.sender);
        _requireValidKickbackRate(_kickbackRate);

        frontEnds[msg.sender].kickbackRate = _kickbackRate;
        frontEnds[msg.sender].registered = true;

        emit FrontEndRegistered(msg.sender, _kickbackRate);
    }

    // --- Stability Pool Deposit Functionality ---

    function _setFrontEndTag(address _depositor, address _frontEndTag) internal {
        deposits[_depositor].frontEndTag = _frontEndTag;
        emit FrontEndTagSet(_depositor, _frontEndTag);
    }

    function _updateDepositAndSnapshots(address _depositor, uint _newValue) internal {
        deposits[_depositor].initialValue = _newValue;

        if (_newValue == 0) {
            delete deposits[_depositor].frontEndTag;
            delete depositSnapshots[_depositor];
            emit DepositSnapshotUpdated(_depositor, 0, 0, 0);
            return;
        }
        uint128 currentScaleCached = currentScale;
        uint128 currentEpochCached = currentEpoch;
        uint currentP = P;

        // Get S and G for the current epoch and current scale
        uint currentS = epochToScaleToSum[currentEpochCached][currentScaleCached];
        uint currentG = epochToScaleToG[currentEpochCached][currentScaleCached];

        // Record new snapshots of the latest running product P, sum S, and sum G, for the depositor
        depositSnapshots[_depositor].P = currentP;
        depositSnapshots[_depositor].S = currentS;
        depositSnapshots[_depositor].G = currentG;
        depositSnapshots[_depositor].scale = currentScaleCached;
        depositSnapshots[_depositor].epoch = currentEpochCached;

        emit DepositSnapshotUpdated(_depositor, currentP, currentS, currentG);
    }

    function _updateFrontEndStakeAndSnapshots(address _frontEnd, uint _newValue) internal {
        frontEndStakes[_frontEnd] = _newValue;

        if (_newValue == 0) {
            delete frontEndSnapshots[_frontEnd];
            emit FrontEndSnapshotUpdated(_frontEnd, 0, 0);
            return;
        }

        uint128 currentScaleCached = currentScale;
        uint128 currentEpochCached = currentEpoch;
        uint currentP = P;

        // Get G for the current epoch and current scale
        uint currentG = epochToScaleToG[currentEpochCached][currentScaleCached];

        // Record new snapshots of the latest running product P and sum G for the front end
        frontEndSnapshots[_frontEnd].P = currentP;
        frontEndSnapshots[_frontEnd].G = currentG;
        frontEndSnapshots[_frontEnd].scale = currentScaleCached;
        frontEndSnapshots[_frontEnd].epoch = currentEpochCached;

        emit FrontEndSnapshotUpdated(_frontEnd, currentP, currentG);
    }

    function _payOutProtocolTokenGains(
        ICommunityIssuance _communityIssuance,
        address _depositor,
        address _frontEnd
    ) internal {
        // Pay out front end's ProtocolToken gain
        if (_frontEnd != address(0)) {
            uint frontEndProtocolTokenGain = getFrontEndProtocolTokenGain(_frontEnd);
            _communityIssuance.sendProtocolToken(_frontEnd, frontEndProtocolTokenGain);
            emit ProtocolTokenPaidToFrontEnd(_frontEnd, frontEndProtocolTokenGain);
        }

        // Pay out depositor's ProtocolToken gain
        uint depositorProtocolTokenGain = getDepositorProtocolTokenGain(_depositor);
        _communityIssuance.sendProtocolToken(_depositor, depositorProtocolTokenGain);
        emit ProtocolTokenPaidToDepositor(_depositor, depositorProtocolTokenGain);
    }

    // --- 'require' functions ---

    function _requireCallerIsActivePool() internal view {
        require(msg.sender == address(activePool), "StabilityPool: Caller is not ActivePool");
    }

    function _requireCallerIsTroveManager() internal view {
        require(msg.sender == address(troveManager), "StabilityPool: Caller is not TroveManager");
    }

    function _requireNoUnderCollateralizedTroves() internal {
        uint price = priceFeed.fetchPrice();
        address lowestTrove = sortedTroves.getLast();
        uint ICR = troveManager.getCurrentICR(lowestTrove, price);
        require(ICR >= MCR, "StabilityPool: Cannot withdraw while there are troves with ICR < MCR");
    }

    function _requireUserHasDeposit(uint _initialDeposit) internal pure {
        require(_initialDeposit > 0, "StabilityPool: User must have a non-zero deposit");
    }

    function _requireUserHasNoDeposit(address _address) internal view {
        uint initialDeposit = deposits[_address].initialValue;
        require(initialDeposit == 0, "StabilityPool: User must have no deposit");
    }

    function _requireNonZeroAmount(uint _amount) internal pure {
        require(_amount > 0, "StabilityPool: Amount must be non-zero");
    }

    function _requireUserHasTrove(address _depositor) internal view {
        require(
            troveManager.getTroveStatus(_depositor) == 1,
            "StabilityPool: caller must have an active trove to withdraw FILGain to"
        );
    }

    function _requireUserHasFILGain(address _depositor) internal view {
        uint FILGain = getDepositorFILGain(_depositor);
        require(FILGain > 0, "StabilityPool: caller must have non-zero FIL Gain");
    }

    function _requireFrontEndNotRegistered(address _address) internal view {
        require(
            !frontEnds[_address].registered,
            "StabilityPool: must not already be a registered front end"
        );
    }

    function _requireFrontEndIsRegisteredOrZero(address _address) internal view {
        require(
            frontEnds[_address].registered || _address == address(0),
            "StabilityPool: Tag must be a registered front end, or the zero address"
        );
    }

    function _requireValidKickbackRate(uint _kickbackRate) internal pure {
        require(
            _kickbackRate <= DECIMAL_PRECISION,
            "StabilityPool: Kickback rate must be in range [0,1]"
        );
    }

    // --- Fallback function ---

    receive() external payable {
        _requireCallerIsActivePool();
        FIL = FIL.add(msg.value);
        emit StabilityPoolFILBalanceUpdated(FIL);
    }
}
