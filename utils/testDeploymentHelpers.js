const { upgrades } = require("hardhat");
const { getContractAddress } = require("@ethersproject/address");

const {
  buildUserProxies,
  BorrowerOperationsProxy,
  BorrowerWrappersProxy,
  TroveManagerProxy,
  StabilityPoolProxy,
  SortedTrovesProxy,
  TokenProxy,
  ProtocolTokenStakingProxy,
} = require("./proxyHelpers.js");

/* "Protocol core" consists of all contracts in the core protocol system.

ProtocolToken contracts consist of only those contracts related to the ProtocolToken:

-the ProtocolToken
-the Lockup factory and lockup contracts
-the ProtocolTokenStaking contract
-the CommunityIssuance contract 
*/

const maxBytes32 = "0x" + "f".repeat(64);
const bootstrapPeriod = 2 * 7 * 24 * 60 * 60; // 2 weeks

upgrades.silenceWarnings();

class DeploymentHelper {
  static factoryCache = {};

  static async getFactory(name) {
    if (!this.factoryCache[name]) {
      this.factoryCache[name] = await ethers.getContractFactory(name);
    }

    return this.factoryCache[name];
  }
  static async deploy(factory, params = []) {
    const contract = await factory.deploy(...params);
    await contract.deployed();

    return contract;
  }

  static async deployProxy(factory, initializationArgs = [], constructorArgs = []) {
    const contract = await upgrades.deployProxy(factory, initializationArgs, {
      unsafeAllow: ["constructor", "state-variable-immutable"],
      constructorArgs: constructorArgs,
    });
    await contract.deployed();

    return contract;
  }

  static async deployProtocolCore(gasCompensation, minNetDebt, cpContracts) {
    const constructorBaseArgs = [gasCompensation, minNetDebt];

    // Get contract factories
    const sortedTrovesFactory = await this.getFactory("SortedTroves");
    const troveManagerFactory = await this.getFactory("TroveManager");
    const activePoolFactory = await this.getFactory("ActivePool");
    const stabilityPoolFactory = await this.getFactory("StabilityPool");
    const gasPoolFactory = await this.getFactory("GasPool");
    const defaultPoolFactory = await this.getFactory("DefaultPool");
    const collSurplusPoolFactory = await this.getFactory("CollSurplusPool");
    const functionCallerFactory = await this.getFactory("FunctionCaller");
    const borrowerOperationsFactory = await this.getFactory("BorrowerOperations");
    const hintHelpersFactory = await this.getFactory("HintHelpers");
    const debtTokenFactory = await this.getFactory("DebtToken");
    const priceFeedTestnetFactory = await this.getFactory("PriceFeedTestnet");

    const sortedTroves = await this.deployProxy(sortedTrovesFactory, [
      maxBytes32,
      cpContracts.troveManager,
      cpContracts.borrowerOperations,
    ]);
    const troveManager = await this.deployProxy(
      troveManagerFactory,
      [
        cpContracts.borrowerOperations,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeedTestnet,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.protocolTokenStaking,
      ],
      [...constructorBaseArgs, bootstrapPeriod],
    );
    const activePool = await this.deployProxy(activePoolFactory, [
      cpContracts.borrowerOperations,
      cpContracts.troveManager,
      cpContracts.stabilityPool,
      cpContracts.defaultPool,
    ]);
    const stabilityPool = await this.deployProxy(
      stabilityPoolFactory,
      [
        cpContracts.borrowerOperations,
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.priceFeedTestnet,
        cpContracts.communityIssuance,
      ],
      constructorBaseArgs,
    );
    const gasPool = await this.deployProxy(gasPoolFactory);
    const defaultPool = await this.deployProxy(defaultPoolFactory, [
      cpContracts.troveManager,
      cpContracts.activePool,
    ]);
    const collSurplusPool = await this.deployProxy(collSurplusPoolFactory, [
      cpContracts.borrowerOperations,
      cpContracts.troveManager,
      cpContracts.activePool,
    ]);
    const functionCaller = await this.deploy(functionCallerFactory);
    const borrowerOperations = await this.deployProxy(
      borrowerOperationsFactory,
      [
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeedTestnet,
        cpContracts.sortedTroves,
        cpContracts.debtToken,
        cpContracts.protocolTokenStaking,
      ],
      constructorBaseArgs,
    );
    const hintHelpers = await this.deployProxy(
      hintHelpersFactory,
      [cpContracts.sortedTroves, cpContracts.troveManager],
      constructorBaseArgs,
    );
    const debtToken = await this.deployProxy(debtTokenFactory, [
      cpContracts.troveManager,
      cpContracts.stabilityPool,
      cpContracts.borrowerOperations,
    ]);
    const priceFeedTestnet = await this.deploy(priceFeedTestnetFactory);

    const coreContracts = {
      priceFeedTestnet,
      debtToken,
      sortedTroves,
      troveManager,
      activePool,
      stabilityPool,
      gasPool,
      defaultPool,
      collSurplusPool,
      functionCaller,
      borrowerOperations,
      hintHelpers,
    };
    return coreContracts;
  }

  static async deployTesterContracts(gasCompensation, minNetDebt, cpContracts) {
    const testerContracts = {};

    const communityIssuanceTesterFactory = await this.getFactory("CommunityIssuanceTester");
    const activePoolTesterFactory = await this.getFactory("ActivePoolTester");
    const defaultPoolTesterFactory = await this.getFactory("DefaultPoolTester");
    const troveManagerTesterFactory = await this.getFactory("TroveManagerTester");
    const stabilityPoolTesterFactory = await this.getFactory("StabilityPoolTester");
    const protocolMathTesterFactory = await this.getFactory("ProtocolMathTester");
    const borrowerOperationsTesterFactory = await this.getFactory("BorrowerOperationsTester");
    const debtTokenTesterFactory = await this.getFactory("DebtTokenTester");

    testerContracts.communityIssuance = await this.deployProxy(communityIssuanceTesterFactory, [
      cpContracts.protocolToken,
      cpContracts.stabilityPool,
    ]);
    testerContracts.activePool = await this.deployProxy(activePoolTesterFactory, [
      cpContracts.borrowerOperations,
      cpContracts.troveManager,
      cpContracts.stabilityPool,
      cpContracts.defaultPool,
    ]);
    testerContracts.defaultPool = await this.deployProxy(defaultPoolTesterFactory, [
      cpContracts.troveManager,
      cpContracts.activePool,
    ]);
    testerContracts.troveManager = await this.deployProxy(
      troveManagerTesterFactory,
      [
        cpContracts.borrowerOperations,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeedTestnet,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.protocolToken,
        cpContracts.protocolTokenStaking,
      ],
      [gasCompensation, minNetDebt],
    );
    testerContracts.stabilityPool = await this.deployProxy(
      stabilityPoolTesterFactory,
      [
        cpContracts.borrowerOperations,
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.priceFeedTestnet,
        cpContracts.communityIssuance,
      ],
      [gasCompensation, minNetDebt],
    );
    testerContracts.math = await this.deploy(protocolMathTesterFactory);
    testerContracts.borrowerOperations = await this.deployProxy(
      borrowerOperationsTesterFactory,
      [
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeedTestnet,
        cpContracts.sortedTroves,
        cpContracts.debtToken,
        cpContracts.protocolTokenStaking,
      ],
      [gasCompensation, minNetDebt],
    );
    testerContracts.debtToken = await this.deployProxy(debtTokenTesterFactory, [
      cpContracts.troveManager,
      cpContracts.stabilityPool,
      cpContracts.borrowerOperations,
    ]);

    return testerContracts;
  }

  static async deployProtocolTokenContracts(annualAllocationRecipient, cpContracts) {
    const protocolTokenStakingFactory = await this.getFactory("ProtocolTokenStaking");
    const lockupContractFactoryFactory = await this.getFactory("LockupContractFactory");
    const communityIssuanceFactory = await this.getFactory("CommunityIssuance");
    const protocolTokenFactory = await this.getFactory("ProtocolToken");

    const protocolTokenStaking = await this.deployProxy(protocolTokenStakingFactory, [
      cpContracts.protocolToken,
      cpContracts.debtToken,
      cpContracts.troveManager,
      cpContracts.borrowerOperations,
      cpContracts.activePool,
    ]);
    const lockupContractFactory = await this.deployProxy(lockupContractFactoryFactory, [
      cpContracts.protocolToken,
    ]);
    const communityIssuance = await this.deployProxy(communityIssuanceFactory, [
      cpContracts.protocolToken,
      cpContracts.stabilityPool,
    ]);
    const protocolToken = await this.deployProxy(protocolTokenFactory, [
      cpContracts.protocolTokenStaking,
      annualAllocationRecipient,
      "20000000000000000", // 2%
    ]);

    const protocolTokenContracts = {
      protocolTokenStaking,
      lockupContractFactory,
      communityIssuance,
      protocolToken,
    };
    return protocolTokenContracts;
  }

  static async deployProtocolTokenTesterContracts(annualAllocationRecipient, cpContracts) {
    const protocolTokenStakingFactory = await this.getFactory("ProtocolTokenStaking");
    const lockupContractFactoryFactory = await this.getFactory("LockupContractFactory");
    const communityIssuanceFactory = await this.getFactory("CommunityIssuanceTester");
    const protocolTokenFactory = await this.getFactory("ProtocolTokenTester");

    const protocolTokenStaking = await this.deployProxy(protocolTokenStakingFactory, [
      cpContracts.protocolToken,
      cpContracts.debtToken,
      cpContracts.troveManager,
      cpContracts.borrowerOperations,
      cpContracts.activePool,
    ]);
    const lockupContractFactory = await this.deployProxy(lockupContractFactoryFactory, [
      cpContracts.protocolToken,
    ]);
    const communityIssuance = await this.deployProxy(communityIssuanceFactory, [
      cpContracts.protocolToken,
      cpContracts.stabilityPool,
    ]);
    const protocolToken = await this.deployProxy(protocolTokenFactory, [
      protocolTokenStaking.address,
      annualAllocationRecipient,
      "20000000000000000", // 2%
    ]);

    const protocolTokenContracts = {
      protocolTokenStaking,
      lockupContractFactory,
      communityIssuance,
      protocolToken,
    };
    return protocolTokenContracts;
  }

  static async deployDebtTokenTester(cpContracts) {
    const debtTokenFactory = await this.getFactory("DebtTokenTester");
    return this.deployProxy(debtTokenFactory, [
      cpContracts.troveManager,
      cpContracts.stabilityPool,
      cpContracts.borrowerOperations,
    ]);
  }

  static async deployTroveManagerTester(gasCompensation, minNetDebt, cpContracts) {
    const troveManagerTesterFactory = await this.getFactory("TroveManagerTester");
    return this.deployProxy(
      troveManagerTesterFactory,
      [
        cpContracts.borrowerOperations,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeedTestnet,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.protocolTokenStaking,
      ],
      [gasCompensation, minNetDebt, bootstrapPeriod],
    );
  }

  static async deployBorrowerOperationsTester(gasCompensation, minNetDebt, cpContracts) {
    const borrowerOperationsTesterFactory = await this.getFactory("BorrowerOperationsTester");
    return this.deployProxy(
      borrowerOperationsTesterFactory,
      [
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeedTestnet,
        cpContracts.sortedTroves,
        cpContracts.debtToken,
        cpContracts.protocolTokenStaking,
      ],
      [gasCompensation, minNetDebt],
    );
  }

  static async deployProxyScripts(contracts, protocolTokenContracts, owner, users) {
    const proxies = await buildUserProxies(users);

    const borrowerWrappersScriptFactory = await this.getFactory("BorrowerWrappersScript");
    const borrowerOperationsScriptFactory = await this.getFactory("BorrowerOperationsScript");
    const troveManagerScriptFactory = await this.getFactory("TroveManagerScript");
    const stabilityPoolScriptFactory = await this.getFactory("StabilityPoolScript");
    const tokenScriptFactory = await this.getFactory("TokenScript");
    const protocolStakingScriptFactory = await this.getFactory("ProtocolStakingScript");

    const borrowerWrappersScript = await this.deploy(borrowerWrappersScriptFactory, [
      contracts.borrowerOperations.address,
      contracts.troveManager.address,
      protocolTokenContracts.protocolTokenStaking.address,
    ]);
    contracts.borrowerWrappers = new BorrowerWrappersProxy(
      owner,
      proxies,
      borrowerWrappersScript.address,
    );

    const borrowerOperationsScript = await this.deploy(borrowerOperationsScriptFactory, [
      contracts.borrowerOperations.address,
    ]);
    contracts.borrowerOperations = new BorrowerOperationsProxy(
      owner,
      proxies,
      borrowerOperationsScript.address,
      contracts.borrowerOperations,
    );

    const troveManagerScript = await this.deploy(troveManagerScriptFactory, [
      contracts.troveManager.address,
    ]);
    contracts.troveManager = new TroveManagerProxy(
      owner,
      proxies,
      troveManagerScript.address,
      contracts.troveManager,
    );

    const stabilityPoolScript = await this.deploy(stabilityPoolScriptFactory, [
      contracts.stabilityPool.address,
    ]);
    contracts.stabilityPool = new StabilityPoolProxy(
      owner,
      proxies,
      stabilityPoolScript.address,
      contracts.stabilityPool,
    );

    contracts.sortedTroves = new SortedTrovesProxy(owner, proxies, contracts.sortedTroves);

    const debtTokenScript = await this.deploy(tokenScriptFactory, [contracts.debtToken.address]);
    contracts.debtToken = new TokenProxy(
      owner,
      proxies,
      debtTokenScript.address,
      contracts.debtToken,
    );

    const protocolTokenScript = await this.deploy(tokenScriptFactory, [
      protocolTokenContracts.protocolToken.address,
    ]);
    protocolTokenContracts.protocolToken = new TokenProxy(
      owner,
      proxies,
      protocolTokenScript.address,
      protocolTokenContracts.protocolToken,
    );

    const protocolTokenStakingScript = await this.deploy(protocolStakingScriptFactory, [
      protocolTokenContracts.protocolTokenStaking.address,
    ]);
    protocolTokenContracts.protocolTokenStaking = new ProtocolTokenStakingProxy(
      owner,
      proxies,
      protocolTokenStakingScript.address,
      protocolTokenContracts.protocolTokenStaking,
    );
  }

  // Connect contracts to their dependencies
  static async connectCoreContracts(contracts, protocolTokenContracts) {
    // set TroveManager addr in SortedTroves
    await contracts.sortedTroves.setParams(
      maxBytes32,
      contracts.troveManager.address,
      contracts.borrowerOperations.address,
    );

    // set contract addresses in the FunctionCaller
    await contracts.functionCaller.setTroveManagerAddress(contracts.troveManager.address);
    await contracts.functionCaller.setSortedTrovesAddress(contracts.sortedTroves.address);

    // set contracts in the Trove Manager
    await contracts.troveManager.setAddresses(
      contracts.borrowerOperations.address,
      contracts.activePool.address,
      contracts.defaultPool.address,
      contracts.stabilityPool.address,
      contracts.gasPool.address,
      contracts.collSurplusPool.address,
      contracts.priceFeedTestnet.address,
      contracts.debtToken.address,
      contracts.sortedTroves.address,
      protocolTokenContracts.protocolToken.address,
      protocolTokenContracts.protocolTokenStaking.address,
    );

    // set contracts in BorrowerOperations
    await contracts.borrowerOperations.setAddresses(
      contracts.troveManager.address,
      contracts.activePool.address,
      contracts.defaultPool.address,
      contracts.stabilityPool.address,
      contracts.gasPool.address,
      contracts.collSurplusPool.address,
      contracts.priceFeedTestnet.address,
      contracts.sortedTroves.address,
      contracts.debtToken.address,
      protocolTokenContracts.protocolTokenStaking.address,
    );

    // set contracts in the Pools
    await contracts.stabilityPool.setAddresses(
      contracts.borrowerOperations.address,
      contracts.troveManager.address,
      contracts.activePool.address,
      contracts.debtToken.address,
      contracts.sortedTroves.address,
      contracts.priceFeedTestnet.address,
      protocolTokenContracts.communityIssuance.address,
    );

    await contracts.activePool.setAddresses(
      contracts.borrowerOperations.address,
      contracts.troveManager.address,
      contracts.stabilityPool.address,
      contracts.defaultPool.address,
    );

    await contracts.defaultPool.setAddresses(
      contracts.troveManager.address,
      contracts.activePool.address,
    );

    await contracts.collSurplusPool.setAddresses(
      contracts.borrowerOperations.address,
      contracts.troveManager.address,
      contracts.activePool.address,
    );

    // set contracts in HintHelpers
    await contracts.hintHelpers.setAddresses(
      contracts.sortedTroves.address,
      contracts.troveManager.address,
    );

    await contracts.debtToken.setAddresses(
      contracts.troveManager.address,
      contracts.stabilityPool.address,
      contracts.borrowerOperations.address,
    );
  }

  static async connectProtocolTokenContracts(protocolTokenContracts) {
    protocolTokenContracts.protocolToken.setAddresses(
      protocolTokenContracts.communityIssuance.address,
      protocolTokenContracts.protocolTokenStaking.address,
      protocolTokenContracts.lockupContractFactory.address,
      protocolTokenContracts.bountyAddress,
      protocolTokenContracts.lpRewardsAddress,
      protocolTokenContracts.multisigAddress,
    );
    // Set ProtocolToken address in LCF
    await protocolTokenContracts.lockupContractFactory.setProtocolTokenAddress(
      protocolTokenContracts.protocolToken.address,
    );
  }

  static async connectProtocolTokenContractsToCore(protocolTokenContracts, coreContracts) {
    await protocolTokenContracts.protocolTokenStaking.setAddresses(
      protocolTokenContracts.protocolToken.address,
      coreContracts.debtToken.address,
      coreContracts.troveManager.address,
      coreContracts.borrowerOperations.address,
      coreContracts.activePool.address,
    );

    await protocolTokenContracts.communityIssuance.setAddresses(
      protocolTokenContracts.protocolToken.address,
      coreContracts.stabilityPool.address,
    );
  }

  static async allocateProtocolToken(protocolTokenContracts, allocation) {
    let communityIssuanceAllocation;
    const { communityIssuance, protocolToken } = protocolTokenContracts;

    const owner = await communityIssuance.owner();
    const accounts = allocation.map((a) => {
      if (a.address === communityIssuance.address) {
        communityIssuanceAllocation = a.amount;
        return owner;
      } else {
        return a.address;
      }
    });
    const amounts = allocation.map((a) => a.amount);

    await protocolToken.triggerInitialAllocation(accounts, amounts);

    if (!!communityIssuanceAllocation) {
      await protocolToken.approve(communityIssuance.address, communityIssuanceAllocation);
      await communityIssuance.startNewEmissionEpoch(communityIssuanceAllocation);
    }
  }

  static async computeContractAddresses(deployer, transactionCount, count) {
    const contractAddresses = [];

    for (let i = 0; i < count; i++) {
      const contractAddress = getContractAddress({
        from: deployer,
        nonce: transactionCount + i,
      });
      contractAddresses.push(contractAddress);
    }

    return contractAddresses;
  }

  static async computeCoreProtocolContracts(deployer, transactionCount) {
    return this.computeContractAddresses(deployer, transactionCount, 30).then((addresses) => ({
      sortedTroves: addresses[1],
      troveManager: addresses[3],
      activePool: addresses[5],
      stabilityPool: addresses[7],
      gasPool: addresses[9],
      defaultPool: addresses[11],
      collSurplusPool: addresses[13],
      functionCaller: addresses[14],
      borrowerOperations: addresses[16],
      hintHelpers: addresses[18],
      debtToken: addresses[20],
      priceFeedTestnet: addresses[21],
      protocolTokenStaking: addresses[23],
      lockupContractFactory: addresses[25],
      communityIssuance: addresses[27],
      protocolToken: addresses[29],
    }));
  }

  static async computeProtocolTokenContracts(deployer, transactionCount) {
    return this.computeContractAddresses(deployer, transactionCount, 4).then((addresses) => ({
      protocolTokenStaking: addresses[0],
      protocolToken: addresses[1],
      lockupContractFactory: addresses[2],
      communityIssuance: addresses[3],
    }));
  }

  static async computeTesterContracts(deployer, transactionCount) {
    return this.computeContractAddresses(deployer, transactionCount, 15).then((addresses) => ({
      communityIssuance: addresses[1],
      activePool: addresses[3],
      defaultPool: addresses[5],
      troveManager: addresses[7],
      stabilityPool: addresses[9],
      math: addresses[10],
      borrowerOperations: addresses[12],
      debtToken: addresses[14],
    }));
  }
}
module.exports = DeploymentHelper;
