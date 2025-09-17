const { UniswapV2Factory } = require("./ABIs/UniswapV2Factory.js");
const { TestHelper: th } = require("../utils/testHelpers.js");
const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const hre = require("hardhat");

async function main(configParams) {
  const date = new Date();
  console.log(date.toUTCString());
  const deployerWallet = (await ethers.getSigners())[0];
  const mdh = new HardhatDeploymentHelper(configParams, deployerWallet);

  const deploymentState = mdh.loadPreviousDeployment();

  console.log(`deployer address: ${deployerWallet.address}`);
  assert.equal(deployerWallet.address, configParams.walletAddrs.DEPLOYER);
  let deployerFILBalance = await ethers.provider.getBalance(deployerWallet.address);
  console.log(`deployerFILBalance before: ${deployerFILBalance}`);

  deployerFILBalance = await ethers.provider.getBalance(deployerWallet.address);
  console.log(`deployer's FIL balance before deployments: ${deployerFILBalance}`);

  const oracleWrapperContracts = await mdh.deployOracleWrappers(deploymentState);
  await mdh.logContractObjects(oracleWrapperContracts);

  // Computed contracts address
  // Note: This contract list order is the same as the order in which the contracts are deployed.
  // This is necessary for the deployment helper to compute the correct addresses.
  const proxyContractList = [
    "priceFeed",
    "sortedTroves",
    "troveManager",
    "activePool",
    "stabilityPool",
    "gasPool",
    "defaultPool",
    "collSurplusPool",
    "borrowerOperations",
    "hintHelpers",
    "debtToken",
    "unipool",
    "protocolTokenStaking",
    "lockupContractFactory",
    "communityIssuance",
    "protocolToken",
  ];

  const addressList = await mdh.computeContractAddresses(proxyContractList.length * 2 + 2);
  const isFirstDeployment = await mdh.isFirstDeployment();

  if (isFirstDeployment) {
    // skip nonces for ProxyAdmin
    addressList.shift();
    addressList.shift();
  }

  const cpContracts = proxyContractList.reduce((acc, contract) => {
    if (deploymentState[contract]) {
      acc[contract] = deploymentState[contract].address;
    } else {
      addressList.shift(); // skip implementation contract
      acc[contract] = addressList.shift();
    }
    return acc;
  }, {});

  // Deploy core logic contracts
  const coreContracts = await mdh.deployProtocolCore(
    oracleWrapperContracts.pythCaller.address,
    oracleWrapperContracts.tellorCaller.address,
    deploymentState,
    cpContracts,
  );
  await mdh.checkContractAddresses(coreContracts, cpContracts);
  await mdh.logContractObjects(coreContracts);

  // Deploy Unipool
  const unipool = await mdh.deployUnipool(deploymentState, cpContracts);
  await mdh.checkContractAddresses({ unipool }, cpContracts);

  // Deploy ProtocolToken Contracts
  const protocolTokenContracts = await mdh.deployProtocolTokenContracts(
    deploymentState,
    cpContracts,
  );
  await mdh.checkContractAddresses(protocolTokenContracts, cpContracts);

  // Deploy a read-only multi-trove getter
  await mdh.deployMultiTroveGetter(deploymentState, cpContracts);

  // Get UniswapV2Factory instance at its deployed address
  const uniswapExits = !!configParams.externalAddrs.UNISWAP_V2_FACTORY;

  if (uniswapExits) {
    const uniswapV2Factory = new ethers.Contract(
      configParams.externalAddrs.UNISWAP_V2_FACTORY,
      UniswapV2Factory.abi,
      deployerWallet,
    );

    console.log(`Uniswp addr: ${uniswapV2Factory.address}`);
    const uniAllPairsLength = await uniswapV2Factory.allPairsLength();
    console.log(`Uniswap Factory number of pairs: ${uniAllPairsLength}`);

    // Check Uniswap Pair DebtToken-FIL pair before pair creation
    let [DebtTokenWFILPairAddr, WFILDebtTokenPairAddr] = await Promise.all([
      uniswapV2Factory.getPair(
        coreContracts.debtToken.address,
        configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
      ),
      uniswapV2Factory.getPair(
        configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
        coreContracts.debtToken.address,
      ),
    ]);
    assert.equal(DebtTokenWFILPairAddr, WFILDebtTokenPairAddr);

    if (DebtTokenWFILPairAddr === th.ZERO_ADDRESS) {
      // Deploy Unipool for DebtToken-WFIL
      await mdh.sendAndWaitForTransaction(
        uniswapV2Factory.createPair(
          configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
          coreContracts.debtToken.address,
        ),
      );

      // Check Uniswap Pair DebtToken-WFIL pair after pair creation (forwards and backwards should have same address)
      DebtTokenWFILPairAddr = await uniswapV2Factory.getPair(
        coreContracts.debtToken.address,
        configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
      );
      assert.notEqual(DebtTokenWFILPairAddr, th.ZERO_ADDRESS);
      WFILDebtTokenPairAddr = await uniswapV2Factory.getPair(
        configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
        coreContracts.debtToken.address,
      );
      console.log(
        `DebtToken-WFIL pair contract address after Uniswap pair creation: ${DebtTokenWFILPairAddr}`,
      );
      assert.equal(WFILDebtTokenPairAddr, DebtTokenWFILPairAddr);
    }
  }

  // Log ProtocolToken and Unipool addresses
  await mdh.logContractObjects(protocolTokenContracts);
  console.log(`Unipool address: ${unipool.address}`);

  // // --- TESTS AND CHECKS  ---

  // Check oracle proxy prices ---

  // Get latest price
  let pythPriceResponse = await oracleWrapperContracts.pythCaller.latestRoundData();
  console.log(`current Pyth price: ${pythPriceResponse[1]}`);
  console.log(`current Pyth timestamp: ${pythPriceResponse[3]}`);

  // Check Tellor price directly (through our TellorCaller)
  let tellorPriceResponse =
    await oracleWrapperContracts.tellorCaller.callStatic.getTellorCurrentValue(); // id == 1: the FIL-USD request ID
  console.log(`current Tellor price: ${tellorPriceResponse[1]}`);
  console.log(`current Tellor timestamp: ${tellorPriceResponse[2]}`);

  // // --- System stats  ---

  // Number of troves
  const numTroves = await coreContracts.troveManager.getTroveOwnersCount();
  console.log(`number of troves: ${numTroves} `);

  // Sorted list size
  const listSize = await coreContracts.sortedTroves.getSize();
  console.log(`Trove list size: ${listSize} `);

  // Total system debt and coll
  const entireSystemDebt = await coreContracts.troveManager.getEntireSystemDebt();
  const entireSystemColl = await coreContracts.troveManager.getEntireSystemColl();
  th.logBN("Entire system debt", entireSystemDebt);
  th.logBN("Entire system coll", entireSystemColl);

  // TCR
  const TCR = await coreContracts.troveManager.getTCR(pythPriceResponse[1]);
  console.log(`TCR: ${TCR}`);

  // current borrowing rate
  const baseRate = await coreContracts.troveManager.baseRate();
  const currentBorrowingRate = await coreContracts.troveManager.getBorrowingRateWithDecay();
  th.logBN("Base rate", baseRate);
  th.logBN("Current borrowing rate", currentBorrowingRate);

  // total SP deposits
  const totalSPDeposits = await coreContracts.stabilityPool.getTotalDebtTokenDeposits();
  th.logBN("Total debt token SP deposits", totalSPDeposits);

  // total ProtocolToken Staked in ProtocolTokenStaking
  const totalProtocolTokenStaked =
    await protocolTokenContracts.protocolTokenStaking.totalProtocolTokenStaked();
  th.logBN("Total ProtocolToken staked", totalProtocolTokenStaked);

  // total LP tokens staked in Unipool
  const totalLPTokensStaked = await unipool.totalSupply();
  th.logBN("Total LP (DebtToken-FIL) tokens staked in unipool", totalLPTokensStaked);

  // --- State variables ---

  // TroveManager
  console.log("TroveManager state variables:");
  const totalStakes = await coreContracts.troveManager.totalStakes();
  const totalStakesSnapshot = await coreContracts.troveManager.totalStakesSnapshot();
  const totalCollateralSnapshot = await coreContracts.troveManager.totalCollateralSnapshot();
  th.logBN("Total trove stakes", totalStakes);
  th.logBN("Snapshot of total trove stakes before last liq. ", totalStakesSnapshot);
  th.logBN("Snapshot of total trove collateral before last liq. ", totalCollateralSnapshot);

  const L_FIL = await coreContracts.troveManager.L_FIL();
  const L_Debt = await coreContracts.troveManager.L_Debt();
  th.logBN("L_FIL", L_FIL);
  th.logBN("L_Debt", L_Debt);

  // StabilityPool
  console.log("StabilityPool state variables:");
  const P = await coreContracts.stabilityPool.P();
  const currentScale = await coreContracts.stabilityPool.currentScale();
  const currentEpoch = await coreContracts.stabilityPool.currentEpoch();
  const S = await coreContracts.stabilityPool.epochToScaleToSum(currentEpoch, currentScale);
  const G = await coreContracts.stabilityPool.epochToScaleToG(currentEpoch, currentScale);
  th.logBN("Product P", P);
  th.logBN("Current epoch", currentEpoch);
  th.logBN("Current scale", currentScale);
  th.logBN("Sum S, at current epoch and scale", S);
  th.logBN("Sum G, at current epoch and scale", G);

  // ProtocolTokenStaking
  console.log("ProtocolTokenStaking state variables:");
  const F_DebtToken = await protocolTokenContracts.protocolTokenStaking.F_DebtToken();
  const F_FIL = await protocolTokenContracts.protocolTokenStaking.F_FIL();
  th.logBN("F_DebtToken", F_DebtToken);
  th.logBN("F_FIL", F_FIL);

  // CommunityIssuance
  console.log("CommunityIssuance state variables:");
  const totalProtocolTokenIssued =
    await protocolTokenContracts.communityIssuance.totalProtocolTokenIssued();
  th.logBN("Total ProtocolToken issued to depositors / front ends", totalProtocolTokenIssued);
}

const inputFile = require(
  `./inputs/${hre.network.name === "localhost" ? "testnet" : hre.network.name}.js`,
);

main(inputFile)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
