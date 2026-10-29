const { readFileSync } = require("fs");
const { task } = require("hardhat/config");
const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const axios = require("axios");
const FormData = require("form-data");

const API_URLS = {
  mainnet: "https://filecoin.blockscout.com/api",
  testnet: "https://filecoin-testnet.blockscout.com/api",
};

// Helper function to get constructor arguments for each contract
const getConstructorArgs = async (fileName, configParams, deploymentState) => {
  const {
    GAS_COMPENSATION,
    MIN_NET_DEBT,
    BOOTSTRAP_PERIOD,
    ORACLE_TIMEOUT,
    LAST_GOOD_PRICE_TIMEOUT,
  } = configParams;
  const constructorBaseArgs = [GAS_COMPENSATION, MIN_NET_DEBT];

  // Get contract addresses from deployment state
  const getAddr = (contractName) => deploymentState[contractName]?.address || "";

  const argsMap = {
    // Non-upgradeable contracts with constructor args
    TellorCaller: [configParams.externalAddrs.TELLOR_MASTER],
    MultiTroveGetter: [getAddr("troveManager"), getAddr("sortedTroves")],

    // Upgradeable contracts with constructor args (passed to implementation contract)
    PriceFeed: [ORACLE_TIMEOUT, LAST_GOOD_PRICE_TIMEOUT],
    TroveManager: [...constructorBaseArgs, BOOTSTRAP_PERIOD],
    StabilityPool: constructorBaseArgs,
    HintHelpers: constructorBaseArgs,
    BorrowerOperations: constructorBaseArgs,

    // Upgradeable contracts without constructor args (only initialize args)
    SortedTroves: [],
    ActivePool: [],
    GasPool: [],
    DefaultPool: [],
    CollSurplusPool: [],
    DebtToken: [],
    Unipool: [],
    CommunityIssuance: [],
    ProtocolTokenStaking: [],
    LockupContractFactory: [],
    ProtocolToken: [],

    // Proxy contract
    TransparentUpgradeableProxy: [], // Proxy itself has constructor args but they're complex
  };

  return argsMap[fileName] || [];
};

// Helper function to get initialization data for proxy contracts
const getInitializationData = async (fileName, configParams, deploymentState) => {
  const maxBytes32 = "0x" + "f".repeat(64);
  const getAddr = (contractName) => deploymentState[contractName]?.address || "";

  // Map of contract names to their initialization arguments
  const initArgsMap = {
    PriceFeed: [getAddr("pythCaller"), getAddr("tellorCaller")],
    SortedTroves: [maxBytes32, getAddr("troveManager"), getAddr("borrowerOperations")],
    TroveManager: [
      getAddr("borrowerOperations"),
      getAddr("activePool"),
      getAddr("defaultPool"),
      getAddr("stabilityPool"),
      getAddr("gasPool"),
      getAddr("collSurplusPool"),
      getAddr("priceFeed"),
      getAddr("debtToken"),
      getAddr("sortedTroves"),
      getAddr("protocolTokenStaking"),
    ],
    ActivePool: [
      getAddr("borrowerOperations"),
      getAddr("troveManager"),
      getAddr("stabilityPool"),
      getAddr("defaultPool"),
    ],
    StabilityPool: [
      getAddr("borrowerOperations"),
      getAddr("troveManager"),
      getAddr("activePool"),
      getAddr("debtToken"),
      getAddr("sortedTroves"),
      getAddr("priceFeed"),
      getAddr("communityIssuance"),
    ],
    GasPool: [],
    DefaultPool: [getAddr("troveManager"), getAddr("activePool")],
    CollSurplusPool: [
      getAddr("borrowerOperations"),
      getAddr("troveManager"),
      getAddr("activePool"),
    ],
    BorrowerOperations: [
      getAddr("troveManager"),
      getAddr("activePool"),
      getAddr("defaultPool"),
      getAddr("stabilityPool"),
      getAddr("gasPool"),
      getAddr("collSurplusPool"),
      getAddr("priceFeed"),
      getAddr("sortedTroves"),
      getAddr("debtToken"),
      getAddr("protocolTokenStaking"),
    ],
    HintHelpers: [getAddr("sortedTroves"), getAddr("troveManager")],
    DebtToken: [getAddr("troveManager"), getAddr("stabilityPool"), getAddr("borrowerOperations")],
    ProtocolTokenStaking: [
      getAddr("protocolToken"),
      getAddr("debtToken"),
      getAddr("troveManager"),
      getAddr("borrowerOperations"),
      getAddr("activePool"),
    ],
    LockupContractFactory: [getAddr("protocolToken")],
    CommunityIssuance: [getAddr("protocolToken"), getAddr("stabilityPool")],
    ProtocolToken: [
      getAddr("protocolTokenStaking"),
      configParams.annualAllocationSettings.RECIPIENT,
      configParams.annualAllocationSettings.RATE,
    ],
    Unipool: [],
  };

  const initArgs = initArgsMap[fileName] || [];
  if (initArgs.length === 0) {
    return "0x";
  }

  // Get the contract factory to encode the initialize function call
  const contractFactory = await ethers.getContractFactory(fileName);
  const initializeFragment = contractFactory.interface.getFunction("initialize");
  const encodedInitData = contractFactory.interface.encodeFunctionData(
    initializeFragment,
    initArgs,
  );

  return encodedInitData;
};

const verifyContract = async (
  network,
  contractAddress,
  sourceCode,
  contractName,
  compilerVersion,
  runs,
  constructorArguments = "",
) => {
  const apiUrl = API_URLS[network];

  // Use Etherscan-compatible API format
  const params = new URLSearchParams({
    module: "contract",
    action: "verifysourcecode",
    contractaddress: contractAddress,
    sourceCode: sourceCode,
    codeformat: "solidity-single-file",
    contractname: contractName,
    compilerversion: compilerVersion,
    optimizationUsed: "1",
    runs,
    constructorArguments: constructorArguments,
    evmversion: "default",
  });

  const opts = {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  };

  try {
    const res = await axios.post(apiUrl, params.toString(), opts);

    if (res.data.status === "1") {
      console.log("Verified:", contractName, "at", contractAddress);
    } else if (res.data.result && res.data.result.includes("Smart-contract already verified")) {
      console.log("Contract already verified:", contractName, "at", contractAddress);
    } else {
      console.log("Verification response:", res.data);
    }
  } catch (error) {
    if (error.response?.data?.result?.includes("Smart-contract already verified")) {
      console.log("Contract already verified:", contractName, "at", contractAddress);
    } else {
      console.error(
        "Error verifying contract:",
        contractName,
        error.response?.data || error.message,
      );
      throw error;
    }
  }
};

task("verify-blockscout", "Verify and register contracts on Blockscout")
  .addOptionalParam("from", "Contract name to resume verification from")
  .setAction(async ({ from }, hre) => {
    const { ethers, network, upgrades } = hre;
    const networkName = network.name === "localhost" ? "testnet" : network.name;
    const configParams = require(`../deployments/inputs/${networkName}.js`);
    const deployer = (await ethers.getSigners())[0];
    const mdh = new HardhatDeploymentHelper(configParams, deployer);
    const deploymentState = mdh.loadPreviousDeployment();

    const filePaths = [
      "Dependencies/TellorCaller.sol",
      "ActivePool.sol",
      "BorrowerOperations.sol",
      "CollSurplusPool.sol",
      "DebtToken.sol",
      "DefaultPool.sol",
      "GasPool.sol",
      "HintHelpers.sol",
      "MultiTroveGetter.sol",
      "PriceFeed.sol",
      "SortedTroves.sol",
      "StabilityPool.sol",
      "TroveManager.sol",
      "LPRewards/Unipool.sol",
      "ProtocolToken/CommunityIssuance.sol",
      "ProtocolToken/LockupContractFactory.sol",
      "ProtocolToken/ProtocolToken.sol",
      "ProtocolToken/ProtocolTokenStaking.sol",
    ];

    let targetFilePaths = filePaths;

    if (from) {
      const startIndex = filePaths.findIndex(
        (filePath) => filePath.split("/").pop().replace(".sol", "") === from,
      );

      if (startIndex === -1) {
        const contractNames = filePaths.map((filePath) =>
          filePath.split("/").pop().replace(".sol", ""),
        );
        throw new Error(
          `Unknown contract specified for --from: ${from}. ` +
            `Available contracts: ${contractNames.join(", ")}`,
        );
      }

      targetFilePaths = filePaths.slice(startIndex);
      console.log(`Resuming verification from ${from}...`);
    }

    for (const filePath of targetFilePaths) {
      const fileName = filePath.split("/").pop().replace(".sol", "");
      const deploymentKey = fileName.charAt(0).toLocaleLowerCase() + fileName.slice(1);
      let contractAddress = deploymentState[deploymentKey].address;

      const content = await hre.run("flatten:get-flattened-sources", {
        files: [`./contracts/${filePath}`],
      });
      const isUpgradeable = content.includes("Upgradeable");

      // Get constructor arguments for this contract
      const constructorArgs = await getConstructorArgs(fileName, configParams, deploymentState);

      // Encode constructor arguments
      let encodedConstructorArgs = "";
      if (constructorArgs.length > 0) {
        const contractFactory = await ethers.getContractFactory(fileName);
        const deployTx = contractFactory.getDeployTransaction(...constructorArgs);
        // Extract constructor args from deployment data
        const contractBytecode = contractFactory.bytecode;
        encodedConstructorArgs = deployTx.data.slice(contractBytecode.length);
      }

      if (isUpgradeable) {
        const proxyContractAddress = contractAddress;
        contractAddress = await upgrades.erc1967.getImplementationAddress(proxyContractAddress);

        // Verify implementation contract
        await verifyContract(
          networkName,
          contractAddress,
          content,
          fileName,
          "v0.7.6+commit.7338295f",
          100,
          encodedConstructorArgs,
        );

        // Verify proxy contract
        const proxyContent = readFileSync(
          `./tasks/utils/flattened/TransparentUpgradeableProxy.sol`,
          "utf8",
        );

        // Get proxy admin address
        const proxyAdminAddress = await upgrades.erc1967.getAdminAddress(proxyContractAddress);

        // Get initialization data for this contract
        const initData = await getInitializationData(fileName, configParams, deploymentState);

        // Encode proxy constructor arguments: (address _logic, address admin_, bytes memory _data)
        const proxyConstructorArgs = ethers.utils.defaultAbiCoder.encode(
          ["address", "address", "bytes"],
          [contractAddress, proxyAdminAddress, initData],
        );

        await verifyContract(
          networkName,
          proxyContractAddress,
          proxyContent,
          "TransparentUpgradeableProxy",
          "v0.8.9+commit.e5eed63a",
          200,
          proxyConstructorArgs.slice(2), // Remove '0x' prefix
        );
      } else {
        // Verify non-upgradeable contract
        await verifyContract(
          networkName,
          contractAddress,
          content,
          fileName,
          "v0.7.6+commit.7338295f",
          100,
          encodedConstructorArgs,
        );
      }
    }
  });
