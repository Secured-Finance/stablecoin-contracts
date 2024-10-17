// Hardhat script
const SortedTroves = artifacts.require("./SortedTroves.sol");
const TroveManager = artifacts.require("./TroveManager.sol");
const PriceFeed = artifacts.require("./PriceFeed.sol");
const DebtToken = artifacts.require("./DebtToken.sol");
const ActivePool = artifacts.require("./ActivePool.sol");
const DefaultPool = artifacts.require("./DefaultPool.sol");
const StabilityPool = artifacts.require("./StabilityPool.sol");
const FunctionCaller = artifacts.require("./FunctionCaller.sol");
const BorrowerOperations = artifacts.require("./BorrowerOperations.sol");

const ProtocolTokenStaking = artifacts.require("./ProtocolToken/ProtocolTokenStaking.sol");
const ProtocolToken = artifacts.require("./ProtocolToken/ProtocolToken.sol");
const LockupContractFactory = artifacts.require("./ProtocolToken/LockupContractFactory.sol");
const CommunityIssuance = artifacts.require("./ProtocolToken/CommunityIssuance.sol");
const HintHelpers = artifacts.require("./HintHelpers.sol");

const CommunityIssuanceTester = artifacts.require("./ProtocolToken/CommunityIssuanceTester.sol");
const ActivePoolTester = artifacts.require("./ActivePoolTester.sol");
const DefaultPoolTester = artifacts.require("./DefaultPoolTester.sol");
const ProtocolMathTester = artifacts.require("./ProtocolMathTester.sol");
const BorrowerOperationsTester = artifacts.require("./BorrowerOperationsTester.sol");
const TroveManagerTester = artifacts.require("./TroveManagerTester.sol");
const DebtTokenTester = artifacts.require("./DebtTokenTester.sol");

const { TestHelper: th } = require("../utils/testHelpers.js");

const dh = require("./deploymentHelpers.js");
const ARBITRARY_ADDRESS = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"; // placeholder for the LPrewards bounty addresses

const coreContractABIs = [
  BorrowerOperations,
  PriceFeed,
  DebtToken,
  SortedTroves,
  TroveManager,
  ActivePool,
  StabilityPool,
  DefaultPool,
  FunctionCaller,
  HintHelpers,
];

const ProtocolTokenContractABIs = [
  ProtocolTokenStaking,
  ProtocolToken,
  LockupContractFactory,
  CommunityIssuance,
];

const TesterContractABIs = [
  CommunityIssuanceTester,
  ActivePoolTester,
  DefaultPoolTester,
  ProtocolMathTester,
  BorrowerOperationsTester,
  TroveManagerTester,
  DebtTokenTester,
];

const getGasFromContractDeployment = async (contractObject, name) => {
  const txHash = contractObject.transactionHash;
  // console.log(`tx hash  of ${name} deployment is is: ${txHash}`)
  const receipt = await ethers.provider.getTransactionReceipt(txHash);
  const gas = receipt.gasUsed;
  console.log(`${name}: ${gas}`);
  return gas;
};

const getBytecodeSize = (contractABI) => {
  const bytecodeLength = contractABI.bytecode.length / 2 - 1;
  const deployedBytecodeLength = contractABI.deployedBytecode.length / 2 - 1;
  console.log(`${contractABI.contractName}: ${bytecodeLength}`);
  // console.log(`${contractABI.contractName} deployed bytecode length: ${deployedBytecodeLength}`)
};

const getUSDCostFromGasCost = (deploymentGasTotal, gasPriceInGwei, FILPrice) => {
  const dollarCost = (deploymentGasTotal * gasPriceInGwei * FILPrice) / 1e9;
  console.log(
    `At gas price ${gasPriceInGwei} GWei, and FIL Price $${FILPrice} per FIL, the total cost of deployment in USD is: $${dollarCost}`,
  );
};

const logContractDeploymentCosts = async (contracts) => {
  console.log(`Gas costs for deployments: `);
  let totalGasCost = 0;
  for (contractName of Object.keys(contracts)) {
    const gasCost = await getGasFromContractDeployment(contracts[contractName], contractName);
    totalGasCost = totalGasCost + Number(gasCost);
  }
  console.log(`Total deployment gas costs: ${totalGasCost}`);
  getUSDCostFromGasCost(totalGasCost, 200, 1850);
};

const logContractObjects = async (contracts) => {
  console.log(`Contract objects addresses:`);
  let totalGasCost = 0;
  for (contractName of Object.keys(contracts)) {
    const gasCost = await getGasFromContractDeployment(contracts[contractName], contractName);
    totalGasCost = totalGasCost + Number(gasCost);
  }
};

const logContractBytecodeLengths = (contractABIs) => {
  console.log(`Contract bytecode lengths:`);
  for (abi of contractABIs) {
    getBytecodeSize(abi);
  }
};

// Run script: log deployment gas costs and bytecode lengths for all contracts
async function main() {
  const coreContracts = await dh.deployProtocolCoreHardhat();
  const protocolTokenContracts = await dh.deployProtocolTokenContractsHardhat(
    ARBITRARY_ADDRESS,
    ARBITRARY_ADDRESS,
  );
  const testerContracts = await dh.deployTesterContractsHardhat(
    th.GAS_COMPENSATION,
    th.MIN_NET_DEBT,
  );

  await dh.connectCoreContracts(coreContracts, protocolTokenContracts);
  await dh.connectProtocolTokenContracts(protocolTokenContracts);
  await dh.connectProtocolTokenContractsToCore(protocolTokenContracts, coreContracts);

  console.log(`\n`);
  console.log(`PROTOCOL TOKEN CONTRACTS`);
  await logContractDeploymentCosts(protocolTokenContracts);
  console.log(`\n`);
  logContractBytecodeLengths(ProtocolTokenContractABIs);
  console.log(`\n`);

  console.log(`CORE CONTRACTS`);
  await logContractDeploymentCosts(coreContracts);
  console.log(`\n`);
  logContractBytecodeLengths(coreContractABIs);
  console.log(`\n`);

  console.log(`TESTER CONTRACTS`);
  await logContractDeploymentCosts(testerContracts);
  console.log(`\n`);
  logContractBytecodeLengths(TesterContractABIs);
  console.log(`\n`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
