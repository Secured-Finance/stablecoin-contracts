const hre = require("hardhat");
const ProxyAdmin = require("@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol/ProxyAdmin.json");
require("dotenv").config();
const { EthersAdapter } = require("@safe-global/protocol-kit");

const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const { MultisigProposal } = require("../utils/multisig.js");

async function main(configParams) {
  const date = new Date();
  console.log(date.toUTCString());
  const deployer = (await ethers.getSigners())[0];
  const mdh = new HardhatDeploymentHelper(configParams, deployer);
  const deploymentState = mdh.loadPreviousDeployment();
  const contractNames = process.env.UPGRADE_CONTRACTS?.split(",") ?? [];
  const constructorBaseArgs = [configParams.GAS_COMPENSATION, configParams.MIN_NET_DEBT];
  const multisig = configParams.walletAddrs.MULTISIG;

  if (contractNames.length === 0) {
    throw new Error("No contracts to upgrade");
  }

  const constructorArgsObj = {
    PriceFeed: [configParams.ORACLE_TIMEOUT, configParams.LAST_GOOD_PRICE_TIMEOUT],
    TroveManager: [...constructorBaseArgs, configParams.BOOTSTRAP_PERIOD],
    StabilityPool: constructorBaseArgs,
    BorrowerOperations: constructorBaseArgs,
    HintHelpers: constructorBaseArgs,
  };

  const adapter = new EthersAdapter({
    ethers: ethers,
    signerOrProvider: deployer,
  });
  const proposal = await MultisigProposal.create(adapter, multisig);

  const proxyAdminFactory = await ethers.getContractFactory(ProxyAdmin.abi, ProxyAdmin.bytecode);

  for (const name of contractNames) {
    const factory = await mdh.getFactory(name);
    const deploymentKey = name.charAt(0).toLocaleLowerCase() + name.slice(1);
    const contractAddress = deploymentState[deploymentKey].address;
    const upgradeProxyArgs = constructorArgsObj[name] ?? [];

    const proxyAdminAddress = await hre.upgrades.erc1967.getAdminAddress(contractAddress);
    const proxyAdminContract = new ethers.Contract(
      proxyAdminAddress,
      proxyAdminFactory.interface,
      deployer,
    );
    const proxyAdminOwner = await proxyAdminContract.owner();

    if (proxyAdminOwner === multisig) {
      const receipt = await mdh.prepareUpgradeProxy(
        factory,
        deploymentKey,
        deploymentState,
        upgradeProxyArgs,
      );

      await proposal.add(
        proxyAdminAddress,
        proxyAdminContract.interface.encodeFunctionData("upgrade", [
          contractAddress,
          receipt.contractAddress,
        ]),
      );
    } else {
      await mdh.upgradeProxy(factory, deploymentKey, deploymentState, upgradeProxyArgs);
    }
  }

  await proposal.submit();
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
