const fs = require("fs");
const { getContractAddress } = require("@ethersproject/address");

const ZERO_ADDRESS = "0x" + "0".repeat(40);
const maxBytes32 = "0x" + "f".repeat(64);

class HardhatDeploymentHelper {
  constructor(configParams, deployerWallet) {
    this.configParams = configParams;
    this.deployerWallet = deployerWallet;
    this.hre = require("hardhat");
    this.outputFile = `./deployments/outputs/${this.hre.network.name}.json`;
  }

  loadPreviousDeployment() {
    let previousDeployment = {};
    if (fs.existsSync(this.outputFile)) {
      console.log(`Loading previous deployment...`);
      previousDeployment = require("../" + this.outputFile);
    }

    return previousDeployment;
  }

  saveDeployment(deploymentState) {
    const deploymentStateJSON = JSON.stringify(deploymentState, null, 2);
    fs.writeFileSync(this.outputFile, deploymentStateJSON);
  }
  // --- Deployer methods ---

  async getFactory(name) {
    const factory = await ethers.getContractFactory(name, this.deployerWallet);
    return factory;
  }

  async sendAndWaitForTransaction(txPromise) {
    const tx = await txPromise;
    return tx.wait();
  }

  async loadOrDeploy(factory, name, deploymentState, constructorArgs = []) {
    if (deploymentState[name] && deploymentState[name].address) {
      console.log(
        `Using previously deployed ${name} contract at address ${deploymentState[name].address}`,
      );
      return new ethers.Contract(
        deploymentState[name].address,
        factory.interface,
        this.deployerWallet,
      );
    }

    console.log(`Deploying ${name} contract...`);

    const contract = await factory.deploy(...constructorArgs);
    await contract.deployTransaction.wait();

    deploymentState[name] = {
      address: contract.address,
      txHashes: [contract.deployTransaction.hash],
    };

    this.saveDeployment(deploymentState);

    return contract;
  }

  async loadOrDeployProxy(
    factory,
    name,
    deploymentState,
    initializationArgs,
    constructorArgs = [],
  ) {
    if (deploymentState[name] && deploymentState[name].address) {
      console.log(
        `Using previously deployed ${name} contract at address ${deploymentState[name].address}`,
      );
      return new ethers.Contract(
        deploymentState[name].address,
        factory.interface,
        this.deployerWallet,
      );
    }

    console.log(`Deploying ${name} contract...`);

    const contract = await this.hre.upgrades.deployProxy(factory, initializationArgs, {
      unsafeAllow: ["constructor", "state-variable-immutable"],
      constructorArgs: constructorArgs,
      redeployImplementation: "always",
      timeout: 3000000,
    });
    await contract.deployTransaction.wait();

    deploymentState[name] = {
      address: contract.address,
      txHashes: [contract.deployTransaction.hash],
    };

    this.saveDeployment(deploymentState);

    return contract;
  }

  async upgradeProxy(factory, name, deploymentState, constructorArgs = []) {
    if (!deploymentState[name] || !deploymentState[name].address) {
      throw new Error(`No deployment state for contract ${name}!!`);
    }

    console.log(`Upgrading ${name} contract...`);

    const contract = await this.hre.upgrades.upgradeProxy(deploymentState[name].address, factory, {
      unsafeAllow: ["constructor", "state-variable-immutable"],
      constructorArgs: constructorArgs,
      timeout: 3000000,
    });
    await contract.deployTransaction.wait();

    deploymentState[name] = {
      address: contract.address,
      txHashes: [...deploymentState[name].txHashes, contract.deployTransaction.hash],
    };

    this.saveDeployment(deploymentState);

    return contract;
  }

  async deployOracleWrappers(deploymentState) {
    const pythPriceFeedAddr = this.configParams.externalAddrs.PYTH_PRICE_FEED;
    const pythPriceId = this.configParams.externalAddrs.PYTH_PRICE_ID;
    const tellorMasterAddr = this.configParams.externalAddrs.TELLOR_MASTER;

    const pythCallerFactory = await this.getFactory("PythCaller");
    const tellorCallerFactory = await this.getFactory("TellorCaller");

    const pythCaller = await this.loadOrDeploy(pythCallerFactory, "pythCaller", deploymentState, [
      pythPriceFeedAddr,
      pythPriceId,
      "FIL / USD",
    ]);

    const tellorCaller = await this.loadOrDeploy(
      tellorCallerFactory,
      "tellorCaller",
      deploymentState,
      [tellorMasterAddr],
    );

    return { pythCaller, tellorCaller };
  }

  async deployProtocolCore(pythCallerAddr, tellorCallerAddr, deploymentState, cpContracts) {
    const constructorBaseArgs = [
      this.configParams.GAS_COMPENSATION,
      this.configParams.MIN_NET_DEBT,
    ];

    // Get contract factories
    const priceFeedFactory = await this.getFactory("PriceFeed");
    const sortedTrovesFactory = await this.getFactory("SortedTroves");
    const troveManagerFactory = await this.getFactory("TroveManager");
    const activePoolFactory = await this.getFactory("ActivePool");
    const stabilityPoolFactory = await this.getFactory("StabilityPool");
    const gasPoolFactory = await this.getFactory("GasPool");
    const defaultPoolFactory = await this.getFactory("DefaultPool");
    const collSurplusPoolFactory = await this.getFactory("CollSurplusPool");
    const borrowerOperationsFactory = await this.getFactory("BorrowerOperations");
    const hintHelpersFactory = await this.getFactory("HintHelpers");
    const debtTokenFactory = await this.getFactory("DebtToken");

    // Deploy txs
    const priceFeed = await this.loadOrDeployProxy(priceFeedFactory, "priceFeed", deploymentState, [
      pythCallerAddr,
      tellorCallerAddr,
    ]);

    const sortedTroves = await this.loadOrDeployProxy(
      sortedTrovesFactory,
      "sortedTroves",
      deploymentState,
      [maxBytes32, cpContracts.troveManager, cpContracts.borrowerOperations],
    );

    const troveManager = await this.loadOrDeployProxy(
      troveManagerFactory,
      "troveManager",
      deploymentState,
      [
        cpContracts.borrowerOperations,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeed,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.protocolToken,
        cpContracts.protocolTokenStaking,
      ],
      [...constructorBaseArgs, this.configParams.BOOTSTRAP_PERIOD],
    );

    const activePool = await this.loadOrDeployProxy(
      activePoolFactory,
      "activePool",
      deploymentState,
      [
        cpContracts.borrowerOperations,
        cpContracts.troveManager,
        cpContracts.stabilityPool,
        cpContracts.defaultPool,
      ],
    );

    const stabilityPool = await this.loadOrDeployProxy(
      stabilityPoolFactory,
      "stabilityPool",
      deploymentState,
      [
        cpContracts.borrowerOperations,
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.debtToken,
        cpContracts.sortedTroves,
        cpContracts.priceFeed,
        cpContracts.communityIssuance,
      ],
      constructorBaseArgs,
    );

    const gasPool = await this.loadOrDeployProxy(gasPoolFactory, "gasPool", deploymentState);

    const defaultPool = await this.loadOrDeployProxy(
      defaultPoolFactory,
      "defaultPool",
      deploymentState,
      [cpContracts.troveManager, cpContracts.activePool],
    );

    const collSurplusPool = await this.loadOrDeployProxy(
      collSurplusPoolFactory,
      "collSurplusPool",
      deploymentState,
      [cpContracts.borrowerOperations, cpContracts.troveManager, cpContracts.activePool],
    );

    const borrowerOperations = await this.loadOrDeployProxy(
      borrowerOperationsFactory,
      "borrowerOperations",
      deploymentState,
      [
        cpContracts.troveManager,
        cpContracts.activePool,
        cpContracts.defaultPool,
        cpContracts.stabilityPool,
        cpContracts.gasPool,
        cpContracts.collSurplusPool,
        cpContracts.priceFeed,
        cpContracts.sortedTroves,
        cpContracts.debtToken,
        cpContracts.protocolTokenStaking,
      ],
      constructorBaseArgs,
    );

    const hintHelpers = await this.loadOrDeployProxy(
      hintHelpersFactory,
      "hintHelpers",
      deploymentState,
      [cpContracts.sortedTroves, cpContracts.troveManager],
      constructorBaseArgs,
    );

    const debtToken = await this.loadOrDeployProxy(debtTokenFactory, "debtToken", deploymentState, [
      cpContracts.troveManager,
      cpContracts.stabilityPool,
      cpContracts.borrowerOperations,
    ]);

    if (!this.configParams.ETHERSCAN_BASE_URL) {
      console.log("No Etherscan Url defined, skipping verification");
    } else {
      await this.verifyContract("priceFeed", deploymentState);
      await this.verifyContract("sortedTroves", deploymentState);
      await this.verifyContract("troveManager", deploymentState);
      await this.verifyContract("activePool", deploymentState);
      await this.verifyContract("stabilityPool", deploymentState);
      await this.verifyContract("gasPool", deploymentState);
      await this.verifyContract("defaultPool", deploymentState);
      await this.verifyContract("collSurplusPool", deploymentState);
      await this.verifyContract("borrowerOperations", deploymentState);
      await this.verifyContract("hintHelpers", deploymentState);
      await this.verifyContract("tellorCaller", deploymentState, [tellorMasterAddr]);
      await this.verifyContract("pythCaller", deploymentState, [
        pythPriceFeedAddr,
        pythPriceId,
        "FIL / USD",
      ]);
      await this.verifyContract("debtToken", deploymentState, debtTokenParams);
    }

    const coreContracts = {
      priceFeed,
      sortedTroves,
      troveManager,
      activePool,
      stabilityPool,
      gasPool,
      defaultPool,
      collSurplusPool,
      borrowerOperations,
      hintHelpers,
      debtToken,
    };
    return coreContracts;
  }

  async deployProtocolTokenContracts(deploymentState, cpContracts) {
    const protocolTokenStakingFactory = await this.getFactory("ProtocolTokenStaking");
    const lockupContractFactory_Factory = await this.getFactory("LockupContractFactory");
    const communityIssuanceFactory = await this.getFactory("CommunityIssuance");
    const protocolTokenFactory = await this.getFactory("ProtocolToken");

    const protocolTokenStaking = await this.loadOrDeployProxy(
      protocolTokenStakingFactory,
      "protocolTokenStaking",
      deploymentState,
      [
        cpContracts.protocolToken,
        cpContracts.debtToken,
        cpContracts.troveManager,
        cpContracts.borrowerOperations,
        cpContracts.activePool,
      ],
    );

    const lockupContractFactory = await this.loadOrDeployProxy(
      lockupContractFactory_Factory,
      "lockupContractFactory",
      deploymentState,
      [cpContracts.protocolToken],
    );

    const communityIssuance = await this.loadOrDeployProxy(
      communityIssuanceFactory,
      "communityIssuance",
      deploymentState,
      [cpContracts.protocolToken, cpContracts.stabilityPool],
    );

    // Deploy ProtocolToken, passing Community Issuance and Factory addresses to the constructor
    const protocolToken = await this.loadOrDeployProxy(
      protocolTokenFactory,
      "protocolToken",
      deploymentState,
      [
        cpContracts.protocolTokenStaking,
        this.configParams.annualAllocationSettings.RECIPIENT,
        this.configParams.annualAllocationSettings.RATE,
      ],
    );

    if (!this.configParams.ETHERSCAN_BASE_URL) {
      console.log("No Etherscan Url defined, skipping verification");
    } else {
      await this.verifyContract("protocolTokenStaking", deploymentState);
      await this.verifyContract("lockupContractFactory", deploymentState);
      await this.verifyContract("communityIssuance", deploymentState);
      await this.verifyContract("protocolToken", deploymentState, protocolTokenParams);
    }

    const protocolTokenContracts = {
      protocolTokenStaking,
      lockupContractFactory,
      communityIssuance,
      protocolToken,
    };
    return protocolTokenContracts;
  }

  async deployUnipool(deploymentState) {
    const unipoolFactory = await this.getFactory("Unipool");
    const unipool = await this.loadOrDeployProxy(unipoolFactory, "unipool", deploymentState);

    if (!this.configParams.ETHERSCAN_BASE_URL) {
      console.log("No Etherscan Url defined, skipping verification");
    } else {
      await this.verifyContract("unipool", deploymentState);
    }

    return unipool;
  }

  async deployMultiTroveGetter(deploymentState, cpContracts) {
    const multiTroveGetterFactory = await this.getFactory("MultiTroveGetter");
    const multiTroveGetterParams = [cpContracts.troveManager, cpContracts.sortedTroves];
    const multiTroveGetter = await this.loadOrDeploy(
      multiTroveGetterFactory,
      "multiTroveGetter",
      deploymentState,
      multiTroveGetterParams,
    );

    if (!this.configParams.ETHERSCAN_BASE_URL) {
      console.log("No Etherscan Url defined, skipping verification");
    } else {
      await this.verifyContract("multiTroveGetter", deploymentState, multiTroveGetterParams);
    }

    return multiTroveGetter;
  }
  // --- Connector methods ---

  async isOwnershipRenounced(contract) {
    const owner = await contract.owner();
    return owner === ZERO_ADDRESS;
  }

  // Connect contracts to their dependencies
  async connectUnipool(uniPool, protocolTokenContracts, DebtTokenWFILPairAddr, duration) {
    (await this.isOwnershipRenounced(uniPool)) ||
      (await this.sendAndWaitForTransaction(
        uniPool.setParams(
          protocolTokenContracts.protocolToken.address,
          DebtTokenWFILPairAddr,
          duration,
        ),
      ));
  }

  // --- Verify on Ethrescan ---
  async verifyContract(name, deploymentState, constructorArguments = []) {
    if (!deploymentState[name] || !deploymentState[name].address) {
      console.error(`  --> No deployment state for contract ${name}!!`);
      return;
    }
    if (deploymentState[name].verification) {
      console.log(`Contract ${name} already verified`);
      return;
    }

    try {
      await this.hre.run("verify:verify", {
        address: deploymentState[name].address,
        constructorArguments,
      });
    } catch (error) {
      // if it was already verified, it’s like a success, so let’s move forward and save it
      if (error.name !== "NomicLabsHardhatPluginError") {
        console.error(`Error verifying: ${error.name}`);
        console.error(error);
        return;
      }
    }

    deploymentState[name].verification =
      `${this.configParams.ETHERSCAN_BASE_URL}/${deploymentState[name].address}#code`;

    this.saveDeployment(deploymentState);
  }

  // --- Helpers ---

  async logContractObjects(contracts) {
    console.log(`Contract objects addresses:`);
    console.table(
      Object.entries(contracts).reduce((acc, [name, contract]) => {
        acc[name] = contract.address;
        return acc;
      }, {}),
    );
  }

  async computeContractAddresses(count) {
    const transactionCount = await this.deployerWallet.getTransactionCount();
    const contractAddresses = [];

    for (let i = 0; i < count; i++) {
      const contractAddress = getContractAddress({
        from: this.deployerWallet.address,
        nonce: transactionCount + i,
      });
      contractAddresses.push(contractAddress);
    }

    return contractAddresses;
  }

  async checkContractAddresses(deployedContracts, cpContractAddresses) {
    for (const [name, contract] of Object.entries(deployedContracts)) {
      const cpContractAddress = cpContractAddresses[name];
      if (contract.address !== cpContractAddress) {
        throw new Error(
          `Contract address mismatch for ${name}: ${contract.address} != ${cpContractAddress}`,
        );
      }
    }
  }
}

module.exports = HardhatDeploymentHelper;
