const hre = require("hardhat");
const { EthersAdapter } = require("@safe-global/protocol-kit");
const ProxyAdmin = require("@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol/ProxyAdmin.json");
const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");
const { MultisigProposal } = require("../utils/multisig.js");

async function main(configParams) {
  const date = new Date();
  console.log(date.toUTCString());
  const deployerWallet = (await ethers.getSigners())[0];
  const mdh = new HardhatDeploymentHelper(configParams, deployerWallet);
  const deploymentState = mdh.loadPreviousDeployment();

  const multisig = configParams.walletAddrs.MULTISIG;

  const [priceFeed, mockPriceFeed] = await Promise.all(
    ["PriceFeed", "MockPriceFeed"].map(async (name) => {
      const factory = await ethers.getContractFactory(name, deployerWallet);
      return new ethers.Contract(
        deploymentState.priceFeed.address,
        factory.interface,
        deployerWallet,
      );
    }),
  );

  const price = await priceFeed.lastGoodPrice();

  const mockAggregator = await mdh.loadOrDeploy(
    await mdh.getFactory("MockAggregator"),
    "mockAggregator",
    deploymentState,
  );

  const proxyAdminFactory = await ethers.getContractFactory(ProxyAdmin.abi, ProxyAdmin.bytecode);
  const proxyAdminAddress = await hre.upgrades.erc1967.getAdminAddress(priceFeed.address);
  const proxyAdminContract = new ethers.Contract(
    proxyAdminAddress,
    proxyAdminFactory.interface,
    deployerWallet,
  );
  const proxyAdminOwner = await proxyAdminContract.owner();

  if (proxyAdminOwner === multisig) {
    const adapter = new EthersAdapter({
      ethers: ethers,
      signerOrProvider: deployerWallet,
    });
    const proposal = await MultisigProposal.create(adapter, multisig);

    const receipt = await mdh.prepareUpgradeProxy(
      await mdh.getFactory("MockPriceFeed"),
      "priceFeed",
      deploymentState,
      [configParams.ORACLE_TIMEOUT, configParams.LAST_GOOD_PRICE_TIMEOUT],
    );

    await proposal.add(
      proxyAdminAddress,
      proxyAdminContract.interface.encodeFunctionData("upgrade", [
        priceFeed.address,
        receipt.contractAddress,
      ]),
    );

    await proposal.add(
      mockPriceFeed.address,
      mockPriceFeed.interface.encodeFunctionData("setPriceAggregator", [
        mockAggregator.address,
        price,
      ]),
    );
    await proposal.submit();
  } else {
    await mdh.upgradeProxy(await mdh.getFactory("MockPriceFeed"), "priceFeed", deploymentState, [
      configParams.ORACLE_TIMEOUT,
      configParams.LAST_GOOD_PRICE_TIMEOUT,
    ]);

    await mdh.sendAndWaitForTransaction(
      mockPriceFeed.setPriceAggregator(mockAggregator.address, price),
    );
  }
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
