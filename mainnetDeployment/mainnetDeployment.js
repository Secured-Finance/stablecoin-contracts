const { UniswapV2Factory } = require("./ABIs/UniswapV2Factory.js");
const { UniswapV2Pair } = require("./ABIs/UniswapV2Pair.js");
const { UniswapV2Router02 } = require("./ABIs/UniswapV2Router02.js");
const { ChainlinkAggregatorV3Interface } = require("./ABIs/ChainlinkAggregatorV3Interface.js");
const { TestHelper: th, TimeValues: timeVals } = require("../utils/testHelpers.js");
const { dec } = th;
const MainnetDeploymentHelper = require("../utils/mainnetDeploymentHelpers.js");
const toBigNum = ethers.BigNumber.from;

async function mainnetDeploy(configParams) {
  const date = new Date();
  console.log(date.toUTCString());
  const deployerWallet = (await ethers.getSigners())[0];
  // const account2Wallet = (await ethers.getSigners())[1]
  const mdh = new MainnetDeploymentHelper(configParams, deployerWallet);

  const deploymentState = mdh.loadPreviousDeployment();

  console.log(`deployer address: ${deployerWallet.address}`);
  assert.equal(deployerWallet.address, configParams.liquityAddrs.DEPLOYER);
  // assert.equal(account2Wallet.address, configParams.beneficiaries.ACCOUNT_2)
  let deployerFILBalance = await ethers.provider.getBalance(deployerWallet.address);
  console.log(`deployerFILBalance before: ${deployerFILBalance}`);

  // Get UniswapV2Factory instance at its deployed address
  const uniswapExits = !!configParams.externalAddrs.UNISWAP_V2_FACTORY;
  const uniswapV2Factory = uniswapExits
    ? new ethers.Contract(
        configParams.externalAddrs.UNISWAP_V2_FACTORY,
        UniswapV2Factory.abi,
        deployerWallet,
      )
    : undefined;

  if (uniswapExits) {
    console.log(`Uniswp addr: ${uniswapV2Factory.address}`);
    const uniAllPairsLength = await uniswapV2Factory.allPairsLength();
    console.log(`Uniswap Factory number of pairs: ${uniAllPairsLength}`);
  }

  deployerFILBalance = await ethers.provider.getBalance(deployerWallet.address);
  console.log(`deployer's FIL balance before deployments: ${deployerFILBalance}`);

  // Deploy core logic contracts
  const liquityCore = await mdh.deployLiquityCoreMainnet(
    configParams.externalAddrs.TELLOR_MASTER,
    configParams.externalAddrs.PYTH_PRICE_FEED,
    configParams.externalAddrs.PYTH_PRICE_ID,
    deploymentState,
  );
  await mdh.logContractObjects(liquityCore);

  // // Check Uniswap Pair DebtToken-FIL pair before pair creation
  // let DebtTokenWFILPairAddr = await uniswapV2Factory.getPair(liquityCore.debtToken.address, configParams.externalAddrs.WRAPPED_NATIVE_TOKEN)
  // let WFILDebtTokenPairAddr = await uniswapV2Factory.getPair(configParams.externalAddrs.WRAPPED_NATIVE_TOKEN, liquityCore.debtToken.address)
  // assert.equal(DebtTokenWFILPairAddr, WFILDebtTokenPairAddr)
  let [DebtTokenWFILPairAddr, WFILDebtTokenPairAddr] = uniswapExits
    ? await Promise.all([
        uniswapV2Factory.getPair(
          liquityCore.debtToken.address,
          configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
        ),
        uniswapV2Factory.getPair(
          configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
          liquityCore.debtToken.address,
        ),
      ])
    : [undefined, undefined];
  assert.equal(DebtTokenWFILPairAddr, WFILDebtTokenPairAddr);

  if (DebtTokenWFILPairAddr === th.ZERO_ADDRESS) {
    // Deploy Unipool for DebtToken-WFIL
    await mdh.sendAndWaitForTransaction(
      uniswapV2Factory.createPair(
        configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
        liquityCore.debtToken.address,
      ),
    );

    // Check Uniswap Pair DebtToken-WFIL pair after pair creation (forwards and backwards should have same address)
    DebtTokenWFILPairAddr = await uniswapV2Factory.getPair(
      liquityCore.debtToken.address,
      configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
    );
    assert.notEqual(DebtTokenWFILPairAddr, th.ZERO_ADDRESS);
    WFILDebtTokenPairAddr = await uniswapV2Factory.getPair(
      configParams.externalAddrs.WRAPPED_NATIVE_TOKEN,
      liquityCore.debtToken.address,
    );
    console.log(
      `DebtToken-WFIL pair contract address after Uniswap pair creation: ${DebtTokenWFILPairAddr}`,
    );
    assert.equal(WFILDebtTokenPairAddr, DebtTokenWFILPairAddr);
  }

  // Deploy Unipool
  const unipool = await mdh.deployUnipoolMainnet(deploymentState);

  // Deploy LQTY Contracts
  const LQTYContracts = await mdh.deployLQTYContractsMainnet(
    configParams.liquityAddrs.GENERAL_SAFE, // bounty address
    unipool.address, // lp rewards address
    configParams.liquityAddrs.LQTY_SAFE, // multisig LQTY endowment address
    deploymentState,
  );

  // Connect all core contracts up
  await mdh.connectCoreContractsMainnet(liquityCore, LQTYContracts);
  await mdh.connectLQTYContractsMainnet(LQTYContracts);
  await mdh.connectLQTYContractsToCoreMainnet(LQTYContracts, liquityCore);

  // Deploy a read-only multi-trove getter
  const multiTroveGetter = await mdh.deployMultiTroveGetterMainnet(liquityCore, deploymentState);

  // Connect Unipool to LQTYToken and the DebtToken-WFIL pair address, with a 6 week duration
  if (uniswapExits) {
    const LPRewardsDuration = timeVals.SECONDS_IN_SIX_WEEKS;
    await mdh.connectUnipoolMainnet(
      unipool,
      LQTYContracts,
      DebtTokenWFILPairAddr,
      LPRewardsDuration,
    );
  }

  // Log LQTY and Unipool addresses
  await mdh.logContractObjects(LQTYContracts);
  console.log(`Unipool address: ${unipool.address}`);

  // let latestBlock = await ethers.provider.getBlockNumber()
  let deploymentStartTime = await LQTYContracts.lqtyToken.getDeploymentStartTime();

  console.log(`deployment start time: ${deploymentStartTime}`);
  const oneYearFromDeployment = (
    Number(deploymentStartTime) + timeVals.SECONDS_IN_ONE_YEAR
  ).toString();
  console.log(`time oneYearFromDeployment: ${oneYearFromDeployment}`);

  // Deploy LockupContracts - one for each beneficiary
  const lockupContracts = {};

  for (const [investor, investorAddr] of Object.entries(configParams.beneficiaries)) {
    const lockupContractEthersFactory = await ethers.getContractFactory(
      "LockupContract",
      deployerWallet,
    );
    if (deploymentState[investor] && deploymentState[investor].address) {
      console.log(
        `Using previously deployed ${investor} lockup contract at address ${deploymentState[investor].address}`,
      );
      lockupContracts[investor] = new ethers.Contract(
        deploymentState[investor].address,
        lockupContractEthersFactory.interface,
        deployerWallet,
      );
    } else {
      const txReceipt = await mdh.sendAndWaitForTransaction(
        LQTYContracts.lockupContractFactory.deployLockupContract(
          investorAddr,
          oneYearFromDeployment,
        ),
      );

      // There is no `logs` in the txReceipt object for a Filecoin deployment. Instead, `queryFilter` is used to get the events
      // const filter = LQTYContracts.lockupContractFactory.filters.LockupContractDeployedThroughFactory()
      // const events = await LQTYContracts.lockupContractFactory.queryFilter(filter, txReceipt.blockNumber)
      // console.log('events:', events)

      const address2 = await txReceipt.logs[0].address; // The deployment event emitted from the LC itself is is the first of two events, so this is its address
      console.log(`address2: ${address2}`);
      // const address = events[0].args._lockupContractAddress
      const address =
        await LQTYContracts.lockupContractFactory.beneficiaryToLockupContract(investorAddr);
      console.log(`address: ${address}`);
      lockupContracts[investor] = new ethers.Contract(
        address,
        lockupContractEthersFactory.interface,
        deployerWallet,
      );

      deploymentState[investor] = {
        address: address,
        txHash: txReceipt.transactionHash,
      };

      mdh.saveDeployment(deploymentState);
    }

    const lqtyTokenAddr = LQTYContracts.lqtyToken.address;
    // verify
    if (configParams.FILERSCAN_BASE_URL) {
      await mdh.verifyContract(investor, deploymentState, [
        lqtyTokenAddr,
        investorAddr,
        oneYearFromDeployment,
      ]);
    }
  }

  // // --- TESTS AND CHECKS  ---

  // Deployer repay DebtToken
  // console.log(`deployer trove debt before repaying: ${await liquityCore.troveManager.getTroveDebt(deployerWallet.address)}`)
  // await mdh.sendAndWaitForTransaction(liquityCore.borrowerOperations.repayDebtToken(dec(800, 18), th.ZERO_ADDRESS, th.ZERO_ADDRESS, {gasPrice, gasLimit: 1000000}))
  // console.log(`deployer trove debt after repaying: ${await liquityCore.troveManager.getTroveDebt(deployerWallet.address)}`)

  // Deployer add coll
  // console.log(`deployer trove coll before adding coll: ${await liquityCore.troveManager.getTroveColl(deployerWallet.address)}`)
  // await mdh.sendAndWaitForTransaction(liquityCore.borrowerOperations.addColl(th.ZERO_ADDRESS, th.ZERO_ADDRESS, {value: dec(2, 'ether'), gasPrice, gasLimit: 1000000}))
  // console.log(`deployer trove coll after addingColl: ${await liquityCore.troveManager.getTroveColl(deployerWallet.address)}`)

  // Check oracle proxy prices ---

  // Get latest price
  let pythPriceResponse = await liquityCore.pythCaller.latestRoundData();
  console.log(`current Pyth price: ${pythPriceResponse[1]}`);
  console.log(`current Pyth timestamp: ${pythPriceResponse[3]}`);

  // Check Tellor price directly (through our TellorCaller)
  let tellorPriceResponse = await liquityCore.tellorCaller.getTellorCurrentValue(); // id == 1: the FIL-USD request ID
  console.log(`current Tellor price: ${tellorPriceResponse[1]}`);
  console.log(`current Tellor timestamp: ${tellorPriceResponse[2]}`);

  // // --- Lockup Contracts ---
  console.log("LOCKUP CONTRACT CHECKS");
  // Check lockup contracts exist for each beneficiary with correct unlock time
  for (investor of Object.keys(lockupContracts)) {
    const lockupContract = lockupContracts[investor];
    // check LC references correct LQTYToken
    const storedLQTYTokenAddr = await lockupContract.lqtyToken();
    assert.equal(LQTYContracts.lqtyToken.address, storedLQTYTokenAddr);
    // Check contract has stored correct beneficary
    const onChainBeneficiary = await lockupContract.beneficiary();
    assert.equal(
      configParams.beneficiaries[investor].toLowerCase(),
      onChainBeneficiary.toLowerCase(),
    );
    // Check correct unlock time (1 yr from deployment)
    const unlockTime = await lockupContract.unlockTime();
    assert.equal(oneYearFromDeployment, unlockTime);

    console.log(
      `lockupContract addr: ${lockupContract.address},
            stored LQTYToken addr: ${storedLQTYTokenAddr}
            beneficiary: ${investor},
            beneficiary addr: ${configParams.beneficiaries[investor]},
            on-chain beneficiary addr: ${onChainBeneficiary},
            unlockTime: ${unlockTime}
            `,
    );
  }

  // // --- Check correct addresses set in LQTYToken
  // console.log("STORED ADDRESSES IN LQTY TOKEN")
  // const storedMultisigAddress = await LQTYContracts.lqtyToken.multisigAddress()
  // assert.equal(configParams.liquityAddrs.LQTY_SAFE.toLowerCase(), storedMultisigAddress.toLowerCase())
  // console.log(`multi-sig address stored in LQTYToken : ${th.squeezeAddr(storedMultisigAddress)}`)
  // console.log(`LQTY Safe address: ${th.squeezeAddr(configParams.liquityAddrs.LQTY_SAFE)}`)

  // // --- LQTY allowances of different addresses ---
  // console.log("INITIAL LQTY BALANCES")
  // // Unipool
  // const unipoolLQTYBal = await LQTYContracts.lqtyToken.balanceOf(unipool.address)
  // // assert.equal(unipoolLQTYBal.toString(), '1333333333333333333333333')
  // th.logBN('Unipool LQTY balance       ', unipoolLQTYBal)

  // // LQTY Safe
  // const lqtySafeBal = await LQTYContracts.lqtyToken.balanceOf(configParams.liquityAddrs.LQTY_SAFE)
  // assert.equal(lqtySafeBal.toString(), '64666666666666666666666667')
  // th.logBN('LQTY Safe balance     ', lqtySafeBal)

  // // Bounties/hackathons (General Safe)
  // const generalSafeBal = await LQTYContracts.lqtyToken.balanceOf(configParams.liquityAddrs.GENERAL_SAFE)
  // assert.equal(generalSafeBal.toString(), '2000000000000000000000000')
  // th.logBN('General Safe balance       ', generalSafeBal)

  // // CommunityIssuance contract
  // const communityIssuanceBal = await LQTYContracts.lqtyToken.balanceOf(LQTYContracts.communityIssuance.address)
  // // assert.equal(communityIssuanceBal.toString(), '32000000000000000000000000')
  // th.logBN('Community Issuance balance', communityIssuanceBal)

  // // --- PriceFeed ---
  // console.log("PRICEFEED CHECKS")
  // // Check Pricefeed's status and last good price
  // const lastGoodPrice = await liquityCore.priceFeed.lastGoodPrice()
  // const priceFeedInitialStatus = await liquityCore.priceFeed.status()
  // th.logBN('PriceFeed first stored price', lastGoodPrice)
  // console.log(`PriceFeed initial status: ${priceFeedInitialStatus}`)

  // // Check PriceFeed's & TellorCaller's stored addresses
  // const priceFeedCLAddress = await liquityCore.priceFeed.priceAggregator()
  // const priceFeedTellorCallerAddress = await liquityCore.priceFeed.tellorCaller()
  // assert.equal(priceFeedCLAddress, configParams.externalAddrs.CHAINLINK_FILUSD_PROXY)
  // assert.equal(priceFeedTellorCallerAddress, liquityCore.tellorCaller.address)

  // // Check Tellor address
  // const tellorCallerTellorMasterAddress = await liquityCore.tellorCaller.tellor()
  // assert.equal(tellorCallerTellorMasterAddress, configParams.externalAddrs.TELLOR_MASTER)

  // // --- Unipool ---

  // // Check Unipool's DebtToken-FIL Uniswap Pair address
  // const unipoolUniswapPairAddr = await unipool.uniToken()
  // console.log(`Unipool's stored DebtToken-FIL Uniswap Pair address: ${unipoolUniswapPairAddr}`)

  // console.log("SYSTEM GLOBAL VARS CHECKS")
  // // --- Sorted Troves ---

  // // Check max size
  // const sortedTrovesMaxSize = (await liquityCore.sortedTroves.data())[2]
  // assert.equal(sortedTrovesMaxSize, '115792089237316195423570985008687907853269984665640564039457584007913129639935')

  // // --- TroveManager ---

  // const liqReserve = await liquityCore.troveManager.GAS_COMPENSATION()
  // const minNetDebt = await liquityCore.troveManager.MIN_NET_DEBT()

  // th.logBN('system liquidation reserve', liqReserve)
  // th.logBN('system min net debt      ', minNetDebt)

  // // --- Make first DebtToken-FIL liquidity provision ---

  // // Open trove if not yet opened
  // const troveStatus = await liquityCore.troveManager.getTroveStatus(deployerWallet.address)
  // if (troveStatus.toString() != '1') {
  //   let _3kDebtTokenWithdrawal = th.dec(3000, 18) // 3000 tokens
  //   let _3FILcoll = th.dec(3, 'ether') // 3 FIL
  //   console.log('Opening trove...')
  //   await mdh.sendAndWaitForTransaction(
  //     liquityCore.borrowerOperations.openTrove(
  //       th._100pct,
  //       _3kDebtTokenWithdrawal,
  //       th.ZERO_ADDRESS,
  //       th.ZERO_ADDRESS,
  //       { value: _3FILcoll, gasPrice }
  //     )
  //   )
  // } else {
  //   console.log('Deployer already has an active trove')
  // }

  // // Check deployer now has an open trove
  // console.log(`deployer is in sorted list after making trove: ${await liquityCore.sortedTroves.contains(deployerWallet.address)}`)

  // const deployerTrove = await liquityCore.troveManager.Troves(deployerWallet.address)
  // th.logBN('deployer debt', deployerTrove[0])
  // th.logBN('deployer coll', deployerTrove[1])
  // th.logBN('deployer stake', deployerTrove[2])
  // console.log(`deployer's trove status: ${deployerTrove[3]}`)

  // // Check deployer has DebtToken
  // let deployerDebtTokenBal = await liquityCore.debtToken.balanceOf(deployerWallet.address)
  // th.logBN("deployer's debt token balance", deployerDebtTokenBal)

  // // Check Uniswap pool has the debt token and WFIL tokens
  const DebtTokenFILPair = uniswapExits
    ? await new ethers.Contract(DebtTokenWFILPairAddr, UniswapV2Pair.abi, deployerWallet)
    : undefined;

  // const token0Addr = await DebtTokenFILPair.token0()
  // const token1Addr = await DebtTokenFILPair.token1()
  // console.log(`DebtToken-FIL Pair token 0: ${th.squeezeAddr(token0Addr)},
  //       DebtToken contract addr: ${th.squeezeAddr(liquityCore.debtToken.address)}`)
  // console.log(`DebtToken-FIL Pair token 1: ${th.squeezeAddr(token1Addr)},
  //       WFIL ERC20 contract addr: ${th.squeezeAddr(configParams.externalAddrs.WRAPPED_NATIVE_TOKEN)}`)

  // // Check initial DebtToken-FIL pair reserves before provision
  // let reserves = await DebtTokenFILPair.getReserves()
  // th.logBN("DebtToken-FIL Pair's DebtToken reserves before provision", reserves[0])
  // th.logBN("DebtToken-FIL Pair's FIL reserves before provision", reserves[1])

  // // Get the UniswapV2Router contract
  // const uniswapV2Router02 = new ethers.Contract(
  //   configParams.externalAddrs.UNISWAP_V2_ROUTER02,
  //   UniswapV2Router02.abi,
  //   deployerWallet
  // )

  // // --- Provide liquidity to DebtToken-FIL pair if not yet done so ---
  // let deployerLPTokenBal = await DebtTokenFILPair.balanceOf(deployerWallet.address)
  // if (deployerLPTokenBal.toString() == '0') {
  //   console.log('Providing liquidity to Uniswap...')
  //   // Give router an allowance for DebtToken
  //   await liquityCore.debtToken.increaseAllowance(uniswapV2Router02.address, dec(10000, 18))

  //   // Check Router's spending allowance
  //   const routerDebtTokenAllowanceFromDeployer = await liquityCore.debtToken.allowance(deployerWallet.address, uniswapV2Router02.address)
  //   th.logBN("router's spending allowance for deployer's debt token", routerDebtTokenAllowanceFromDeployer)

  //   // Get amounts for liquidity provision
  //   const LP_FIL = dec(1, 'ether')

  //   // Convert 8-digit CL price to 18 and multiply by FIL amount
  //   const debtTokenAmount = toBigNum(chainlinkPrice)
  //     .mul(toBigNum(dec(1, 10)))
  //     .mul(toBigNum(LP_FIL))
  //     .div(toBigNum(dec(1, 18)))

  //   const minDebtTokenAmount = debtTokenAmount.sub(toBigNum(dec(100, 18)))

  //   latestBlock = await ethers.provider.getBlockNumber()
  //   now = (await ethers.provider.getBlock(latestBlock)).timestamp
  //   let tenMinsFromNow = now + (60 * 60 * 10)

  //   // Provide liquidity to DebtToken-FIL pair
  //   await mdh.sendAndWaitForTransaction(
  //     uniswapV2Router02.addLiquidityFIL(
  //       liquityCore.debtToken.address, // address of debt token
  //       debtTokenAmount, // debt token provision
  //       minDebtTokenAmount, // minimum debt token provision
  //       LP_FIL, // minimum FIL provision
  //       deployerWallet.address, // address to send LP tokens to
  //       tenMinsFromNow, // deadline for this tx
  //       {
  //         value: dec(1, 'ether'),
  //         gasPrice,
  //         gasLimit: 5000000 // For some reason, ethers can't estimate gas for this tx
  //       }
  //     )
  //   )
  // } else {
  //   console.log('Liquidity already provided to Uniswap')
  // }
  // // Check DebtToken-FIL reserves after liquidity provision:
  // reserves = await DebtTokenFILPair.getReserves()
  // th.logBN("DebtToken-FIL Pair's DebtToken reserves after provision", reserves[0])
  // th.logBN("DebtToken-FIL Pair's FIL reserves after provision", reserves[1])

  // // ---  Check LP staking  ---
  // console.log("CHECK LP STAKING EARNS LQTY")

  // // Check deployer's LP tokens
  // deployerLPTokenBal = await DebtTokenFILPair.balanceOf(deployerWallet.address)
  // th.logBN("deployer's LP token balance", deployerLPTokenBal)

  // // Stake LP tokens in Unipool
  // console.log(`DebtTokenFILPair addr: ${DebtTokenFILPair.address}`)
  // console.log(`Pair addr stored in Unipool: ${await unipool.uniToken()}`)

  // earnedLQTY = await unipool.earned(deployerWallet.address)
  // th.logBN("deployer's farmed LQTY before staking LP tokens", earnedLQTY)

  // const deployerUnipoolStake = await unipool.balanceOf(deployerWallet.address)
  // if (deployerUnipoolStake.toString() == '0') {
  //   console.log('Staking to Unipool...')
  //   // Deployer approves Unipool
  //   await mdh.sendAndWaitForTransaction(
  //     DebtTokenFILPair.approve(unipool.address, deployerLPTokenBal, { gasPrice })
  //   )

  //   await mdh.sendAndWaitForTransaction(unipool.stake(1, { gasPrice }))
  // } else {
  //   console.log('Already staked in Unipool')
  // }

  // console.log("wait 90 seconds before checking earnings... ")
  // await configParams.waitFunction()

  // earnedLQTY = await unipool.earned(deployerWallet.address)
  // th.logBN("deployer's farmed LQTY from Unipool after waiting ~1.5mins", earnedLQTY)

  // let deployerLQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployerWallet.address)
  // th.logBN("deployer LQTY Balance Before SP deposit", deployerLQTYBal)

  // // --- Make SP deposit and earn LQTY ---
  // console.log("CHECK DEPLOYER MAKING DEPOSIT AND EARNING LQTY")

  // let SPDeposit = await liquityCore.stabilityPool.getCompoundedDebtTokenDeposit(deployerWallet.address)
  // th.logBN("deployer SP deposit before making deposit", SPDeposit)

  // // Provide to SP
  // await mdh.sendAndWaitForTransaction(liquityCore.stabilityPool.provideToSP(dec(15, 18), th.ZERO_ADDRESS, { gasPrice, gasLimit: 400000 }))

  // // Get SP deposit
  // SPDeposit = await liquityCore.stabilityPool.getCompoundedDebtTokenDeposit(deployerWallet.address)
  // th.logBN("deployer SP deposit after depositing 15 tokens", SPDeposit)

  // console.log("wait 90 seconds before withdrawing...")
  // // wait 90 seconds
  // await configParams.waitFunction()

  // // Withdraw from SP
  // // await mdh.sendAndWaitForTransaction(liquityCore.stabilityPool.withdrawFromSP(dec(1000, 18), { gasPrice, gasLimit: 400000 }))

  // // SPDeposit = await liquityCore.stabilityPool.getCompoundedDebtTokenDeposit(deployerWallet.address)
  // // th.logBN("deployer SP deposit after full withdrawal", SPDeposit)

  // // deployerLQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployerWallet.address)
  // // th.logBN("deployer LQTY Balance after SP deposit withdrawal", deployerLQTYBal)

  // // ---  Attempt withdrawal from LC  ---
  // console.log("CHECK BENEFICIARY ATTEMPTING WITHDRAWAL FROM LC")

  // // connect Acct2 wallet to the LC they are beneficiary of
  // let account2LockupContract = await lockupContracts["ACCOUNT_2"].connect(account2Wallet)

  // // Deployer funds LC with 10 LQTY
  // // await mdh.sendAndWaitForTransaction(LQTYContracts.lqtyToken.transfer(account2LockupContract.address, dec(10, 18), { gasPrice }))

  // // account2 LQTY bal
  // let account2bal = await LQTYContracts.lqtyToken.balanceOf(account2Wallet.address)
  // th.logBN("account2 LQTY bal before withdrawal attempt", account2bal)

  // // Check LC LQTY bal
  // let account2LockupContractBal = await LQTYContracts.lqtyToken.balanceOf(account2LockupContract.address)
  // th.logBN("account2's LC LQTY bal before withdrawal attempt", account2LockupContractBal)

  // // Acct2 attempts withdrawal from  LC
  // await mdh.sendAndWaitForTransaction(account2LockupContract.withdrawLQTY({ gasPrice, gasLimit: 1000000 }))

  // // Acct LQTY bal
  // account2bal = await LQTYContracts.lqtyToken.balanceOf(account2Wallet.address)
  // th.logBN("account2's LQTY bal after LC withdrawal attempt", account2bal)

  // // Check LC bal
  // account2LockupContractBal = await LQTYContracts.lqtyToken.balanceOf(account2LockupContract.address)
  // th.logBN("account2's LC LQTY bal LC withdrawal attempt", account2LockupContractBal)

  // // --- Stake LQTY ---
  // console.log("CHECK DEPLOYER STAKING LQTY")

  // // Log deployer LQTY bal and stake before staking
  // deployerLQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployerWallet.address)
  // th.logBN("deployer LQTY bal before staking", deployerLQTYBal)
  // let deployerLQTYStake = await LQTYContracts.lqtyStaking.stakes(deployerWallet.address)
  // th.logBN("deployer stake before staking", deployerLQTYStake)

  // // stake 13 LQTY
  // await mdh.sendAndWaitForTransaction(LQTYContracts.lqtyStaking.stake(dec(13, 18), { gasPrice, gasLimit: 1000000 }))

  // // Log deployer LQTY bal and stake after staking
  // deployerLQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployerWallet.address)
  // th.logBN("deployer LQTY bal after staking", deployerLQTYBal)
  // deployerLQTYStake = await LQTYContracts.lqtyStaking.stakes(deployerWallet.address)
  // th.logBN("deployer stake after staking", deployerLQTYStake)

  // // Log deployer rev share immediately after staking
  // let deployerDebtTokenRevShare = await LQTYContracts.lqtyStaking.getPendingDebtTokenGain(deployerWallet.address)
  // th.logBN("deployer pending debt token revenue share", deployerDebtTokenRevShare)

  // // --- 2nd Account opens trove ---
  // const trove2Status = await liquityCore.troveManager.getTroveStatus(account2Wallet.address)
  // if (trove2Status.toString() != '1') {
  //   console.log("Acct 2 opens a trove ...")
  //   let _2kDebtTokenWithdrawal = th.dec(2000, 18) // 2000 tokens
  //   let _1pt5_FILcoll = th.dec(15, 17) // 1.5 FIL
  //   const borrowerOpsEthersFactory = await ethers.getContractFactory("BorrowerOperations", account2Wallet)
  //   const borrowerOpsAcct2 = await new ethers.Contract(liquityCore.borrowerOperations.address, borrowerOpsEthersFactory.interface, account2Wallet)

  //   await mdh.sendAndWaitForTransaction(borrowerOpsAcct2.openTrove(th._100pct, _2kDebtTokenWithdrawal, th.ZERO_ADDRESS, th.ZERO_ADDRESS, { value: _1pt5_FILcoll, gasPrice, gasLimit: 1000000 }))
  // } else {
  //   console.log('Acct 2 already has an active trove')
  // }

  // const acct2Trove = await liquityCore.troveManager.Troves(account2Wallet.address)
  // th.logBN('acct2 debt', acct2Trove[0])
  // th.logBN('acct2 coll', acct2Trove[1])
  // th.logBN('acct2 stake', acct2Trove[2])
  // console.log(`acct2 trove status: ${acct2Trove[3]}`)

  // // Log deployer's pending debt token gain - check fees went to staker (deloyer)
  // deployerDebtTokenRevShare = await LQTYContracts.lqtyStaking.getPendingDebtTokenGain(deployerWallet.address)
  // th.logBN("deployer pending debt token revenue share from staking, after acct 2 opened trove", deployerDebtTokenRevShare)

  // //  --- deployer withdraws staking gains ---
  // console.log("CHECK DEPLOYER WITHDRAWING STAKING GAINS")

  // // check deployer's debt token balance before withdrawing staking gains
  // deployerDebtTokenBal = await liquityCore.debtToken.balanceOf(deployerWallet.address)
  // th.logBN('deployer debt token bal before withdrawing staking gains', deployerDebtTokenBal)

  // // Deployer withdraws staking gains
  // await mdh.sendAndWaitForTransaction(LQTYContracts.lqtyStaking.unstake(0, { gasPrice, gasLimit: 1000000 }))

  // // check deployer's debt token balance after withdrawing staking gains
  // deployerDebtTokenBal = await liquityCore.debtToken.balanceOf(deployerWallet.address)
  // th.logBN('deployer debt token bal after withdrawing staking gains', deployerDebtTokenBal)

  // // --- System stats  ---

  // Uniswap DebtToken-FIL pool size
  if (uniswapExits) {
    let reserves = await DebtTokenFILPair.getReserves();
    th.logBN("DebtToken-FIL Pair's current debt token reserves", reserves[0]);
    th.logBN("DebtToken-FIL Pair's current FIL reserves", reserves[1]);
  }

  // Number of troves
  const numTroves = await liquityCore.troveManager.getTroveOwnersCount();
  console.log(`number of troves: ${numTroves} `);

  // Sorted list size
  const listSize = await liquityCore.sortedTroves.getSize();
  console.log(`Trove list size: ${listSize} `);

  // Total system debt and coll
  const entireSystemDebt = await liquityCore.troveManager.getEntireSystemDebt();
  const entireSystemColl = await liquityCore.troveManager.getEntireSystemColl();
  th.logBN("Entire system debt", entireSystemDebt);
  th.logBN("Entire system coll", entireSystemColl);

  // TCR
  const TCR = await liquityCore.troveManager.getTCR(pythPriceResponse[1]);
  console.log(`TCR: ${TCR}`);

  // current borrowing rate
  const baseRate = await liquityCore.troveManager.baseRate();
  const currentBorrowingRate = await liquityCore.troveManager.getBorrowingRateWithDecay();
  th.logBN("Base rate", baseRate);
  th.logBN("Current borrowing rate", currentBorrowingRate);

  // total SP deposits
  const totalSPDeposits = await liquityCore.stabilityPool.getTotalDebtTokenDeposits();
  th.logBN("Total debt token SP deposits", totalSPDeposits);

  // total LQTY Staked in LQTYStaking
  const totalLQTYStaked = await LQTYContracts.lqtyStaking.totalLQTYStaked();
  th.logBN("Total LQTY staked", totalLQTYStaked);

  // total LP tokens staked in Unipool
  const totalLPTokensStaked = await unipool.totalSupply();
  th.logBN("Total LP (DebtToken-FIL) tokens staked in unipool", totalLPTokensStaked);

  // --- State variables ---

  // TroveManager
  console.log("TroveManager state variables:");
  const totalStakes = await liquityCore.troveManager.totalStakes();
  const totalStakesSnapshot = await liquityCore.troveManager.totalStakesSnapshot();
  const totalCollateralSnapshot = await liquityCore.troveManager.totalCollateralSnapshot();
  th.logBN("Total trove stakes", totalStakes);
  th.logBN("Snapshot of total trove stakes before last liq. ", totalStakesSnapshot);
  th.logBN("Snapshot of total trove collateral before last liq. ", totalCollateralSnapshot);

  const L_FIL = await liquityCore.troveManager.L_FIL();
  const L_Debt = await liquityCore.troveManager.L_Debt();
  th.logBN("L_FIL", L_FIL);
  th.logBN("L_Debt", L_Debt);

  // StabilityPool
  console.log("StabilityPool state variables:");
  const P = await liquityCore.stabilityPool.P();
  const currentScale = await liquityCore.stabilityPool.currentScale();
  const currentEpoch = await liquityCore.stabilityPool.currentEpoch();
  const S = await liquityCore.stabilityPool.epochToScaleToSum(currentEpoch, currentScale);
  const G = await liquityCore.stabilityPool.epochToScaleToG(currentEpoch, currentScale);
  th.logBN("Product P", P);
  th.logBN("Current epoch", currentEpoch);
  th.logBN("Current scale", currentScale);
  th.logBN("Sum S, at current epoch and scale", S);
  th.logBN("Sum G, at current epoch and scale", G);

  // LQTYStaking
  console.log("LQTYStaking state variables:");
  const F_DebtToken = await LQTYContracts.lqtyStaking.F_DebtToken();
  const F_FIL = await LQTYContracts.lqtyStaking.F_FIL();
  th.logBN("F_DebtToken", F_DebtToken);
  th.logBN("F_FIL", F_FIL);

  // CommunityIssuance
  console.log("CommunityIssuance state variables:");
  const totalLQTYIssued = await LQTYContracts.communityIssuance.totalLQTYIssued();
  th.logBN("Total LQTY issued to depositors / front ends", totalLQTYIssued);

  // TODO: Uniswap *LQTY-FIL* pool size (check it's deployed?)

  // ************************
  // --- NOT FOR APRIL 5: Deploy a LQTYToken2 with General Safe as beneficiary to test minting LQTY showing up in Gnosis App  ---

  // // General Safe LQTY bal before:
  // const realGeneralSafeAddr = "0xF06016D822943C42e3Cb7FC3a6A3B1889C1045f8"

  //   const LQTYToken2EthersFactory = await ethers.getContractFactory("LQTYToken2", deployerWallet)
  //   const lqtyToken2 = await LQTYToken2EthersFactory.deploy(
  //     "0xF41E0DD45d411102ed74c047BdA544396cB71E27",  // CI param: LC1
  //     "0x9694a04263593AC6b895Fc01Df5929E1FC7495fA", // LQTY Staking param: LC2
  //     "0x98f95E112da23c7b753D8AE39515A585be6Fb5Ef", // LCF param: LC3
  //     realGeneralSafeAddr,  // bounty/hackathon param: REAL general safe addr
  //     "0x98f95E112da23c7b753D8AE39515A585be6Fb5Ef", // LP rewards param: LC3
  //     deployerWallet.address, // multisig param: deployer wallet
  //     {gasPrice, gasLimit: 10000000}
  //   )

  //   console.log(`lqty2 address: ${lqtyToken2.address}`)

  //   let generalSafeLQTYBal = await lqtyToken2.balanceOf(realGeneralSafeAddr)
  //   console.log(`generalSafeLQTYBal: ${generalSafeLQTYBal}`)

  // ************************
  // --- NOT FOR APRIL 5: Test short-term lockup contract LQTY withdrawal on mainnet ---

  // now = (await ethers.provider.getBlock(latestBlock)).timestamp

  // const LCShortTermEthersFactory = await ethers.getContractFactory("LockupContractShortTerm", deployerWallet)

  // new deployment
  // const LCshortTerm = await LCShortTermEthersFactory.deploy(
  //   LQTYContracts.lqtyToken.address,
  //   deployerWallet.address,
  //   now,
  //   {gasPrice, gasLimit: 1000000}
  // )

  // LCshortTerm.deployTransaction.wait()

  // existing deployment
  // const deployedShortTermLC = await new ethers.Contract(
  //   "0xbA8c3C09e9f55dA98c5cF0C28d15Acb927792dC7",
  //   LCShortTermEthersFactory.interface,
  //   deployerWallet
  // )

  // new deployment
  // console.log(`Short term LC Address:  ${LCshortTerm.address}`)
  // console.log(`recorded beneficiary in short term LC:  ${await LCshortTerm.beneficiary()}`)
  // console.log(`recorded short term LC name:  ${await LCshortTerm.NAME()}`)

  // existing deployment
  //   console.log(`Short term LC Address:  ${deployedShortTermLC.address}`)
  //   console.log(`recorded beneficiary in short term LC:  ${await deployedShortTermLC.beneficiary()}`)
  //   console.log(`recorded short term LC name:  ${await deployedShortTermLC.NAME()}`)
  //   console.log(`recorded short term LC name:  ${await deployedShortTermLC.unlockTime()}`)
  //   now = (await ethers.provider.getBlock(latestBlock)).timestamp
  //   console.log(`time now: ${now}`)

  //   // check deployer LQTY bal
  //   let deployerLQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployerWallet.address)
  //   console.log(`deployerLQTYBal before he withdraws: ${deployerLQTYBal}`)

  //   // check LC LQTY bal
  //   let LC_LQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployedShortTermLC.address)
  //   console.log(`LC LQTY bal before withdrawal: ${LC_LQTYBal}`)

  // // withdraw from LC
  // const withdrawFromShortTermTx = await deployedShortTermLC.withdrawLQTY( {gasPrice, gasLimit: 1000000})
  // withdrawFromShortTermTx.wait()

  // // check deployer bal after LC withdrawal
  // deployerLQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployerWallet.address)
  // console.log(`deployerLQTYBal after he withdraws: ${deployerLQTYBal}`)

  //   // check LC LQTY bal
  //   LC_LQTYBal = await LQTYContracts.lqtyToken.balanceOf(deployedShortTermLC.address)
  //   console.log(`LC LQTY bal after withdrawal: ${LC_LQTYBal}`)
}

module.exports = {
  mainnetDeploy,
};
