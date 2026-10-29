const axios = require("axios");
const { readFileSync } = require("fs");
const { task } = require("hardhat/config");

const HardhatDeploymentHelper = require("../utils/hardhatDeploymentHelpers.js");

const API_URLS = {
  mainnet: "https://filfox.info/api/v1/tools/verifyContract",
  testnet: "https://calibration.filfox.info/api/v1/tools/verifyContract",
};

const stringifyCompilerSetting = (value) => {
  if (value === undefined) {
    return "";
  }

  return typeof value === "string" ? value : JSON.stringify(value);
};

const getSourceFiles = (buildInfo, sourceName) => {
  const sourceNames = new Set();
  let hasMissingAst = false;

  const addSourceAndImports = (currentSourceName) => {
    if (sourceNames.has(currentSourceName)) {
      return;
    }

    if (!buildInfo.input.sources[currentSourceName]) {
      throw new Error(`Source not found in build info: ${currentSourceName}`);
    }

    sourceNames.add(currentSourceName);

    const ast = buildInfo.output.sources[currentSourceName]?.ast;
    if (!ast) {
      hasMissingAst = true;
      return;
    }

    for (const node of ast.nodes) {
      if (node.nodeType === "ImportDirective") {
        addSourceAndImports(node.absolutePath);
      }
    }
  };

  addSourceAndImports(sourceName);

  // Without every AST, the complete import graph cannot be determined safely.
  // In that case, preserve the exact compiler input by submitting every source.
  const selectedSources = hasMissingAst
    ? Object.entries(buildInfo.input.sources)
    : [...sourceNames].map((name) => [name, buildInfo.input.sources[name]]);

  return Object.fromEntries(
    selectedSources.map(([name, source]) => [name, { content: source.content }]),
  );
};

const verifyContract = async (
  network,
  name,
  contractAddress,
  { compiler, sourceFiles, compilerSettings = {} },
) => {
  const optimizer = compilerSettings.optimizer ?? { enabled: true };
  const opts = {
    headers: { "Content-Type": "application/json" },
  };

  const body = {
    address: contractAddress,
    language: "Solidity",
    compiler,
    optimize: optimizer.enabled ?? false,
    optimizeRuns: optimizer.runs,
    optimizerDetails: stringifyCompilerSetting(optimizer.details),
    sourceFiles,
    evmVersion: compilerSettings.evmVersion ?? "default",
    viaIR: compilerSettings.viaIR ?? false,
    libraries: stringifyCompilerSetting(compilerSettings.libraries),
    metadata: stringifyCompilerSetting(compilerSettings.metadata),
  };

  const res = await axios.post(API_URLS[network], body, opts);

  if (res.data.success) {
    console.log("Verified:", name);
  } else {
    if (res.data.errorCode === 6) {
      console.log("Contract already verified:", name);
    } else {
      console.log("res:", res.data);
      throw new Error(
        `Contract verification failed: ${name} (Filfox errorCode ${res.data.errorCode})`,
      );
    }
  }
};

task("verify-filfox", "Verify and register contracts on Filfox").setAction(
  async (_, { run, artifacts, ethers, network, upgrades }) => {
    const networkName = network.name === "localhost" ? "testnet" : network.name;
    const configParams = require(`../deployments/inputs/${networkName}.js`);
    const deployer = (await ethers.getSigners())[0];
    const mdh = new HardhatDeploymentHelper(configParams, deployer);
    const deploymentState = mdh.loadPreviousDeployment();

    const filePaths = [
      "Dependencies/PythCaller.sol",
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

    for (const filePath of filePaths) {
      const fileName = filePath.split("/").pop().replace(".sol", "");
      const deploymentKey = fileName.charAt(0).toLocaleLowerCase() + fileName.slice(1);
      let contractAddress = deploymentState[deploymentKey].address;

      const content = await run("flatten:get-flattened-sources", {
        files: [`./contracts/${filePath}`],
      });
      const isUpgradeable = content.includes("Upgradeable");

      if (isUpgradeable) {
        const proxyContractAddress = contractAddress;
        contractAddress = await upgrades.erc1967.getImplementationAddress(proxyContractAddress);
        const content = readFileSync(
          `./tasks/utils/flattened/TransparentUpgradeableProxy.sol`,
          "utf8",
        );

        await verifyContract(networkName, `${fileName} (Proxy)`, proxyContractAddress, {
          compiler: "v0.8.9+commit.e5eed63a",
          sourceFiles: {
            ["TransparentUpgradeableProxy.sol"]: { content },
          },
          compilerSettings: {
            optimizer: { enabled: true },
          },
        });
      }

      const sourceName = `contracts/${filePath}`;
      const fullyQualifiedName = `${sourceName}:${fileName}`;
      const buildInfo = await artifacts.getBuildInfo(fullyQualifiedName);

      if (!buildInfo) {
        throw new Error(`Build info not found for ${fullyQualifiedName}`);
      }

      await verifyContract(
        networkName,
        isUpgradeable ? `${fileName} (Implementation)` : fileName,
        contractAddress,
        {
          compiler: `v${buildInfo.solcLongVersion}`,
          sourceFiles: getSourceFiles(buildInfo, sourceName),
          compilerSettings: buildInfo.input.settings,
        },
      );
    }
  },
);
