// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

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
 * Please see the implementation spec in the proof document, which closely follows on from the compounded deposit / FIL gain derivations:
 * https://github.com/liquity/liquity/blob/master/papers/Scalable_Reward_Distribution_with_Compounding_Stakes.pdf
 *
 * --- PROTOCOL TOKEN ISSUANCE TO STABILITY POOL DEPOSITORS ---
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
 */
interface IStabilityPool {
    // --- Events ---

    event StabilityPoolFILBalanceUpdated(uint _newBalance);
    event StabilityPoolDebtTokenBalanceUpdated(uint _newBalance);

    event BorrowerOperationsAddressChanged(address _newBorrowerOperationsAddress);
    event TroveManagerAddressChanged(address _newTroveManagerAddress);
    event ActivePoolAddressChanged(address _newActivePoolAddress);
    event DebtTokenAddressChanged(address _newDebtTokenAddress);
    event SortedTrovesAddressChanged(address _newSortedTrovesAddress);
    event PriceFeedAddressChanged(address _newPriceFeedAddress);
    event CommunityIssuanceAddressChanged(address _newCommunityIssuanceAddress);

    event P_Updated(uint _P);
    event S_Updated(uint _S, uint128 _epoch, uint128 _scale);
    event G_Updated(uint _G, uint128 _epoch, uint128 _scale);
    event EpochUpdated(uint128 _currentEpoch);
    event ScaleUpdated(uint128 _currentScale);

    event FrontEndRegistered(address indexed _frontEnd, uint _kickbackRate);
    event FrontEndTagSet(address indexed _depositor, address indexed _frontEnd);

    event DepositSnapshotUpdated(address indexed _depositor, uint _P, uint _S, uint _G);
    event FrontEndSnapshotUpdated(address indexed _frontEnd, uint _P, uint _G);
    event UserDepositChanged(address indexed _depositor, uint _newDeposit);
    event FrontEndStakeChanged(
        address indexed _frontEnd,
        uint _newFrontEndStake,
        address _depositor
    );

    event FILGainWithdrawn(address indexed _depositor, uint _FIL, uint _debtTokenLoss);
    event ProtocolTokenPaidToDepositor(address indexed _depositor, uint _protocolToken);
    event ProtocolTokenPaidToFrontEnd(address indexed _frontEnd, uint _protocolToken);
    event FILSent(address _to, uint _amount);

    // --- Functions ---

    /*
     * Initial checks:
     * - Frontend is registered or zero address
     * - Sender is not a registered frontend
     * - _amount is not zero
     * ---
     * - Triggers a ProtocolToken issuance, based on time passed since the last issuance. The ProtocolToken issuance is shared between *all* depositors and front ends
     * - Tags the deposit with the provided front end tag param, if it's a new deposit
     * - Sends depositor's accumulated gains (ProtocolToken, FIL) to depositor
     * - Sends the tagged front end's accumulated ProtocolToken gains to the tagged front end
     * - Increases deposit and tagged front end's stake, and takes new snapshots for each.
     */
    function provideToSP(uint _amount, address _frontEndTag) external;

    /*
     * Initial checks:
     * - _amount is zero or there are no under collateralized troves left in the system
     * - User has a non zero deposit
     * ---
     * - Triggers a ProtocolToken issuance, based on time passed since the last issuance. The ProtocolToken issuance is shared between *all* depositors and front ends
     * - Removes the deposit's front end tag if it is a full withdrawal
     * - Sends all depositor's accumulated gains (ProtocolToken, FIL) to depositor
     * - Sends the tagged front end's accumulated ProtocolToken gains to the tagged front end
     * - Decreases deposit and tagged front end's stake, and takes new snapshots for each.
     *
     * If _amount > userDeposit, the user withdraws all of their compounded deposit.
     */
    function withdrawFromSP(uint _amount) external;

    /*
     * Initial checks:
     * - User has a non zero deposit
     * - User has an open trove
     * - User has some FIL gain
     * ---
     * - Triggers a ProtocolToken issuance, based on time passed since the last issuance. The ProtocolToken issuance is shared between *all* depositors and front ends
     * - Sends all depositor's ProtocolToken gain to  depositor
     * - Sends all tagged front end's ProtocolToken gain to the tagged front end
     * - Transfers the depositor's entire FIL gain from the Stability Pool to the caller's trove
     * - Leaves their compounded deposit in the Stability Pool
     * - Updates snapshots for deposit and tagged front end stake
     */
    function withdrawFILGainToTrove(address _upperHint, address _lowerHint) external;

    /*
     * Initial checks:
     * - Frontend (sender) not already registered
     * - User (sender) has no deposit
     * - _kickbackRate is in the range [0, 100%]
     * ---
     * Front end makes a one-time selection of kickback rate upon registering
     */
    function registerFrontEnd(uint _kickbackRate) external;

    /*
     * Initial checks:
     * - Caller is TroveManager
     * ---
     * Cancels out the specified debt against the debt token contained in the Stability Pool (as far as possible)
     * and transfers the Trove's FIL collateral from ActivePool to StabilityPool.
     * Only called by liquidation functions in the TroveManager.
     */
    function offset(uint _debt, uint _coll) external;

    /*
     * Returns the total amount of FIL held by the pool, accounted in an internal variable instead of `balance`,
     * to exclude edge cases like FIL received from a self-destruct.
     */
    function getFIL() external view returns (uint);

    /*
     * Returns debt token held in the pool. Changes when users deposit/withdraw, and when Trove debt is offset.
     */
    function getTotalDebtTokenDeposits() external view returns (uint);

    /*
     * Calculates the FIL gain earned by the deposit since its last snapshots were taken.
     */
    function getDepositorFILGain(address _depositor) external view returns (uint);

    /*
     * Calculate the ProtocolToken gain earned by a deposit since its last snapshots were taken.
     * If not tagged with a front end, the depositor gets a 100% cut of what their deposit earned.
     * Otherwise, their cut of the deposit's earnings is equal to the kickbackRate, set by the front end through
     * which they made their deposit.
     */
    function getDepositorProtocolTokenGain(address _depositor) external view returns (uint);

    /*
     * Return the ProtocolToken gain earned by the front end.
     */
    function getFrontEndProtocolTokenGain(address _frontEnd) external view returns (uint);

    /*
     * Return the user's compounded deposit.
     */
    function getCompoundedDebtTokenDeposit(address _depositor) external view returns (uint);

    /*
     * Return the front end's compounded stake.
     *
     * The front end's compounded stake is equal to the sum of its depositors' compounded deposits.
     */
    function getCompoundedFrontEndStake(address _frontEnd) external view returns (uint);

    /*
     * Fallback function
     * Only callable by Active Pool, it just accounts for FIL received
     * receive() external payable;
     */
}
