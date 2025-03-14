// SPDX-License-Identifier: MIT

pragma solidity 0.7.6;

import "../TroveManager.sol";
import "../Interfaces/ITroveManager.sol";
import "../BorrowerOperations.sol";
import "../ActivePool.sol";
import "../DefaultPool.sol";
import "../StabilityPool.sol";
import "../GasPool.sol";
import "../CollSurplusPool.sol";
import "../DebtToken.sol";
import "./PriceFeedTestnet.sol";
import "../SortedTroves.sol";
import "../ProtocolToken/ProtocolToken.sol";
import "../ProtocolToken/ProtocolTokenStaking.sol";
import "../ProtocolToken/CommunityIssuance.sol";

import "./EchidnaProxy.sol";
//import "../Dependencies/console.sol";

contract EchidnaTester {
    using SafeMath for uint;

    uint private constant NUMBER_OF_ACTORS = 100;
    uint private constant INITIAL_BALANCE = 1e24;
    uint private constant GAS_COMPENSATION = 20000000000000000000;
    uint private constant MIN_NET_DEBT = 180000000000000000000;
    uint private constant BOOTSTRAP_PERIOD = 14 days;
    uint private MCR;
    uint private CCR;

    TroveManager public troveManager;
    BorrowerOperations public borrowerOperations;
    ActivePool public activePool;
    DefaultPool public defaultPool;
    StabilityPool public stabilityPool;
    GasPool public gasPool;
    CollSurplusPool public collSurplusPool;
    DebtToken public debtToken;
    PriceFeedTestnet priceFeedTestnet;
    SortedTroves sortedTroves;

    ProtocolToken public protocolToken;
    ProtocolTokenStaking public protocolTokenStaking;
    CommunityIssuance public communityIssuance;

    EchidnaProxy[NUMBER_OF_ACTORS] public echidnaProxies;

    uint private numberOfTroves;

    constructor() payable {
        troveManager = new TroveManager(GAS_COMPENSATION, MIN_NET_DEBT, BOOTSTRAP_PERIOD);
        borrowerOperations = new BorrowerOperations(GAS_COMPENSATION, MIN_NET_DEBT);
        activePool = new ActivePool();
        defaultPool = new DefaultPool();
        stabilityPool = new StabilityPool(GAS_COMPENSATION, MIN_NET_DEBT);
        gasPool = new GasPool();
        debtToken = new DebtToken();

        collSurplusPool = new CollSurplusPool();
        priceFeedTestnet = new PriceFeedTestnet();

        sortedTroves = new SortedTroves();

        protocolToken = new ProtocolToken();
        protocolTokenStaking = new ProtocolTokenStaking();
        communityIssuance = new CommunityIssuance();

        troveManager.initialize(
            address(borrowerOperations),
            address(activePool),
            address(defaultPool),
            address(stabilityPool),
            address(gasPool),
            address(collSurplusPool),
            address(priceFeedTestnet),
            address(debtToken),
            address(sortedTroves),
            address(protocolTokenStaking)
        );

        borrowerOperations.initialize(
            address(troveManager),
            address(activePool),
            address(defaultPool),
            address(stabilityPool),
            address(gasPool),
            address(collSurplusPool),
            address(priceFeedTestnet),
            address(sortedTroves),
            address(debtToken),
            address(protocolTokenStaking)
        );

        activePool.initialize(
            address(borrowerOperations),
            address(troveManager),
            address(stabilityPool),
            address(defaultPool)
        );

        defaultPool.initialize(address(troveManager), address(activePool));

        stabilityPool.initialize(
            address(borrowerOperations),
            address(troveManager),
            address(activePool),
            address(debtToken),
            address(sortedTroves),
            address(priceFeedTestnet),
            address(communityIssuance)
        );

        debtToken.initialize(
            address(troveManager),
            address(stabilityPool),
            address(borrowerOperations)
        );

        collSurplusPool.initialize(
            address(borrowerOperations),
            address(troveManager),
            address(activePool)
        );

        sortedTroves.initialize(1e18, address(troveManager), address(borrowerOperations));

        protocolToken.initialize(address(protocolTokenStaking), msg.sender, 40000000000000000);

        protocolTokenStaking.initialize(
            address(protocolToken),
            address(debtToken),
            address(troveManager),
            address(borrowerOperations),
            address(activePool)
        );

        communityIssuance.initialize(address(protocolToken), address(stabilityPool));

        for (uint i = 0; i < NUMBER_OF_ACTORS; i++) {
            echidnaProxies[i] = new EchidnaProxy(
                troveManager,
                borrowerOperations,
                stabilityPool,
                debtToken
            );
            (bool success, ) = address(echidnaProxies[i]).call{value: INITIAL_BALANCE}("");
            require(success);
        }

        MCR = borrowerOperations.MCR();
        CCR = borrowerOperations.CCR();

        require(MCR > 0);
        require(CCR > 0);

        // TODO:
        priceFeedTestnet.setPrice(1e22);
    }

    // TroveManager

    function liquidateExt(uint _i, address _user) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].liquidatePrx(_user);
    }

    function liquidateTrovesExt(uint _i, uint _n) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].liquidateTrovesPrx(_n);
    }

    function batchLiquidateTrovesExt(uint _i, address[] calldata _troveArray) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].batchLiquidateTrovesPrx(_troveArray);
    }

    function redeemCollateralExt(
        uint _i,
        uint _debtTokenAmount,
        address _firstRedemptionHint,
        address _upperPartialRedemptionHint,
        address _lowerPartialRedemptionHint,
        uint _partialRedemptionHintNICR
    ) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].redeemCollateralPrx(
            _debtTokenAmount,
            _firstRedemptionHint,
            _upperPartialRedemptionHint,
            _lowerPartialRedemptionHint,
            _partialRedemptionHintNICR,
            0,
            0
        );
    }

    // Borrower Operations

    function getAdjustedFIL(uint actorBalance, uint _FIL, uint ratio) internal view returns (uint) {
        uint price = priceFeedTestnet.getPrice();
        require(price > 0);
        uint minFIL = ratio.mul(GAS_COMPENSATION).div(price);
        require(actorBalance > minFIL);
        uint FIL = minFIL + (_FIL % (actorBalance - minFIL));
        return FIL;
    }

    function getAdjustedDebtAmount(
        uint FIL,
        uint _debtTokenAmount,
        uint ratio
    ) internal view returns (uint) {
        uint price = priceFeedTestnet.getPrice();
        uint debtTokenAmount = _debtTokenAmount;
        uint compositeDebt = debtTokenAmount.add(GAS_COMPENSATION);
        uint ICR = ProtocolMath._computeCR(FIL, compositeDebt, price);
        if (ICR < ratio) {
            compositeDebt = FIL.mul(price).div(ratio);
            debtTokenAmount = compositeDebt.sub(GAS_COMPENSATION);
        }
        return debtTokenAmount;
    }

    function openTroveExt(uint _i, uint _FIL, uint _debtTokenAmount) public payable {
        uint actor = _i % NUMBER_OF_ACTORS;
        EchidnaProxy echidnaProxy = echidnaProxies[actor];
        uint actorBalance = address(echidnaProxy).balance;

        // we pass in CCR instead of MCR in case it’s the first one
        uint FIL = getAdjustedFIL(actorBalance, _FIL, CCR);
        uint debtTokenAmount = getAdjustedDebtAmount(FIL, _debtTokenAmount, CCR);

        //console.log('FIL', FIL);
        //console.log('debtTokenAmount', debtTokenAmount);

        echidnaProxy.openTrovePrx(FIL, debtTokenAmount, address(0), address(0), 10000000000000000);

        numberOfTroves = troveManager.getTroveOwnersCount();
        assert(numberOfTroves > 0);
        // canary
        //assert(numberOfTroves == 0);
    }

    function openTroveRawExt(
        uint _i,
        uint _FIL,
        uint _debtTokenAmount,
        address _upperHint,
        address _lowerHint,
        uint _maxFee
    ) public payable {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].openTrovePrx(_FIL, _debtTokenAmount, _upperHint, _lowerHint, _maxFee);
    }

    function addCollExt(uint _i, uint _FIL) external payable {
        uint actor = _i % NUMBER_OF_ACTORS;
        EchidnaProxy echidnaProxy = echidnaProxies[actor];
        uint actorBalance = address(echidnaProxy).balance;

        uint FIL = getAdjustedFIL(actorBalance, _FIL, MCR);

        echidnaProxy.addCollPrx(FIL, address(0), address(0));
    }

    function addCollRawExt(
        uint _i,
        uint _FIL,
        address _upperHint,
        address _lowerHint
    ) external payable {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].addCollPrx(_FIL, _upperHint, _lowerHint);
    }

    function withdrawCollExt(
        uint _i,
        uint _amount,
        address _upperHint,
        address _lowerHint
    ) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].withdrawCollPrx(_amount, _upperHint, _lowerHint);
    }

    function withdrawDebtTokenExt(
        uint _i,
        uint _amount,
        address _upperHint,
        address _lowerHint,
        uint _maxFee
    ) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].withdrawDebtTokenPrx(_amount, _upperHint, _lowerHint, _maxFee);
    }

    function repayDebtTokenExt(
        uint _i,
        uint _amount,
        address _upperHint,
        address _lowerHint
    ) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].repayDebtTokenPrx(_amount, _upperHint, _lowerHint);
    }

    function closeTroveExt(uint _i) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].closeTrovePrx();
    }

    function adjustTroveExt(
        uint _i,
        uint _FIL,
        uint _collWithdrawal,
        uint _debtChange,
        bool _isDebtIncrease
    ) external payable {
        uint actor = _i % NUMBER_OF_ACTORS;
        EchidnaProxy echidnaProxy = echidnaProxies[actor];
        uint actorBalance = address(echidnaProxy).balance;

        uint FIL = getAdjustedFIL(actorBalance, _FIL, MCR);
        uint debtChange = _debtChange;
        if (_isDebtIncrease) {
            // TODO: add current amount already withdrawn:
            debtChange = getAdjustedDebtAmount(FIL, uint(_debtChange), MCR);
        }
        // TODO: collWithdrawal, debtChange
        echidnaProxy.adjustTrovePrx(
            FIL,
            _collWithdrawal,
            debtChange,
            _isDebtIncrease,
            address(0),
            address(0),
            0
        );
    }

    function adjustTroveRawExt(
        uint _i,
        uint _FIL,
        uint _collWithdrawal,
        uint _debtChange,
        bool _isDebtIncrease,
        address _upperHint,
        address _lowerHint,
        uint _maxFee
    ) external payable {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].adjustTrovePrx(
            _FIL,
            _collWithdrawal,
            _debtChange,
            _isDebtIncrease,
            _upperHint,
            _lowerHint,
            _maxFee
        );
    }

    // Pool Manager

    function provideToSPExt(uint _i, uint _amount, address _frontEndTag) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].provideToSPPrx(_amount, _frontEndTag);
    }

    function withdrawFromSPExt(uint _i, uint _amount) external {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].withdrawFromSPPrx(_amount);
    }

    // Debt Token

    function transferExt(uint _i, address recipient, uint256 amount) external returns (bool) {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].transferPrx(recipient, amount);
        return true;
    }

    function approveExt(uint _i, address spender, uint256 amount) external returns (bool) {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].approvePrx(spender, amount);
        return true;
    }

    function transferFromExt(
        uint _i,
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        uint actor = _i % NUMBER_OF_ACTORS;
        echidnaProxies[actor].transferFromPrx(sender, recipient, amount);
        return true;
    }

    // PriceFeed

    function setPriceExt(uint256 _price) external {
        bool result = priceFeedTestnet.setPrice(_price);
        assert(result);
    }

    // --------------------------
    // Invariants and properties
    // --------------------------

    function echidna_canary_number_of_troves() public view returns (bool) {
        if (numberOfTroves > 20) {
            return false;
        }

        return true;
    }

    function echidna_canary_active_pool_balance() public view returns (bool) {
        if (address(activePool).balance > 0) {
            return false;
        }
        return true;
    }

    function echidna_troves_order() external view returns (bool) {
        address currentTrove = sortedTroves.getFirst();
        address nextTrove = sortedTroves.getNext(currentTrove);

        while (currentTrove != address(0) && nextTrove != address(0)) {
            if (troveManager.getNominalICR(nextTrove) > troveManager.getNominalICR(currentTrove)) {
                return false;
            }
            // Uncomment to check that the condition is meaningful
            //else return false;

            currentTrove = nextTrove;
            nextTrove = sortedTroves.getNext(currentTrove);
        }

        return true;
    }

    /**
     * Status
     * Minimum debt (gas compensation)
     * Stake > 0
     */
    function echidna_trove_properties() public view returns (bool) {
        address currentTrove = sortedTroves.getFirst();
        while (currentTrove != address(0)) {
            // Status
            if (
                ITroveManager.Status(troveManager.getTroveStatus(currentTrove)) !=
                ITroveManager.Status.active
            ) {
                return false;
            }
            // Uncomment to check that the condition is meaningful
            //else return false;

            // Minimum debt (gas compensation)
            if (troveManager.getTroveDebt(currentTrove) < GAS_COMPENSATION) {
                return false;
            }
            // Uncomment to check that the condition is meaningful
            //else return false;

            // Stake > 0
            if (troveManager.getTroveStake(currentTrove) == 0) {
                return false;
            }
            // Uncomment to check that the condition is meaningful
            //else return false;

            currentTrove = sortedTroves.getNext(currentTrove);
        }
        return true;
    }

    function echidna_FIL_balances() public view returns (bool) {
        if (address(troveManager).balance > 0) {
            return false;
        }

        if (address(borrowerOperations).balance > 0) {
            return false;
        }

        if (address(activePool).balance != activePool.getFIL()) {
            return false;
        }

        if (address(defaultPool).balance != defaultPool.getFIL()) {
            return false;
        }

        if (address(stabilityPool).balance != stabilityPool.getFIL()) {
            return false;
        }

        if (address(debtToken).balance > 0) {
            return false;
        }

        if (address(priceFeedTestnet).balance > 0) {
            return false;
        }

        if (address(sortedTroves).balance > 0) {
            return false;
        }

        return true;
    }

    // TODO: What should we do with this? Should it be allowed? Should it be a canary?
    function echidna_price() public view returns (bool) {
        uint price = priceFeedTestnet.getPrice();

        if (price == 0) {
            return false;
        }
        // Uncomment to check that the condition is meaningful
        //else return false;

        return true;
    }

    // Total debt token matches
    function echidna_debt_token_global_balances() public view returns (bool) {
        uint totalSupply = debtToken.totalSupply();
        uint gasPoolBalance = debtToken.balanceOf(address(gasPool));

        uint activePoolBalance = activePool.getDebt();
        uint defaultPoolBalance = defaultPool.getDebt();
        if (totalSupply != activePoolBalance + defaultPoolBalance) {
            return false;
        }

        uint stabilityPoolBalance = stabilityPool.getTotalDebtTokenDeposits();
        address currentTrove = sortedTroves.getFirst();
        uint trovesBalance;
        while (currentTrove != address(0)) {
            trovesBalance += debtToken.balanceOf(address(currentTrove));
            currentTrove = sortedTroves.getNext(currentTrove);
        }
        // we cannot state equality because tranfers are made to external addresses too
        if (totalSupply <= stabilityPoolBalance + trovesBalance + gasPoolBalance) {
            return false;
        }

        return true;
    }

    // function echidna_test() public view returns (bool) {
    //     return true;
    // }
}
