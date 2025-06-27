const BigNumber = require("bignumber.js");

const MoneyValues = {
  negative_5e17: "-" + web3.utils.toWei("500", "finney"),
  negative_1e18: "-" + web3.utils.toWei("1", "ether"),
  negative_10e18: "-" + web3.utils.toWei("10", "ether"),
  negative_50e18: "-" + web3.utils.toWei("50", "ether"),
  negative_100e18: "-" + web3.utils.toWei("100", "ether"),
  negative_101e18: "-" + web3.utils.toWei("101", "ether"),
  negative_eth: (amount) => "-" + web3.utils.toWei(amount, "ether"),

  _zeroBN: ethers.BigNumber.from("0"),
  _1e18BN: ethers.BigNumber.from("1000000000000000000"),
  _10e18BN: ethers.BigNumber.from("10000000000000000000"),
  _100e18BN: ethers.BigNumber.from("100000000000000000000"),
  _100BN: ethers.BigNumber.from("100"),
  _110BN: ethers.BigNumber.from("110"),
  _150BN: ethers.BigNumber.from("150"),

  _MCR: ethers.BigNumber.from("1100000000000000000"),
  _ICR100: ethers.BigNumber.from("1000000000000000000"),
  _CCR: ethers.BigNumber.from("1500000000000000000"),
};

const TimeValues = {
  SECONDS_IN_ONE_MINUTE: 60,
  SECONDS_IN_ONE_HOUR: 60 * 60,
  SECONDS_IN_ONE_DAY: 60 * 60 * 24,
  SECONDS_IN_ONE_WEEK: 60 * 60 * 24 * 7,
  SECONDS_IN_SIX_WEEKS: 60 * 60 * 24 * 7 * 6,
  SECONDS_IN_ONE_MONTH: 60 * 60 * 24 * 30,
  SECONDS_IN_ONE_YEAR: 60 * 60 * 24 * 365,
  MINUTES_IN_ONE_WEEK: 60 * 24 * 7,
  MINUTES_IN_ONE_MONTH: 60 * 24 * 30,
  MINUTES_IN_ONE_YEAR: 60 * 24 * 365,
};

const getRevertReason = async (txHash) => {
  const trace = await hre.network.provider.send("debug_traceTransaction", [txHash]);
  const revertOutput = trace?.returnValue;

  if (revertOutput?.startsWith("0x08c379a0")) {
    const reasonHex = "0x" + revertOutput.slice(10);
    const reason = ethers.utils.defaultAbiCoder.decode(["string"], reasonHex);
    return reason[0];
  } else if (revertOutput !== "0x") {
    console.warn("Raw revert output:", revertOutput);
    return null;
  } else {
    console.warn("No revert data found.");
    return null;
  }
};

class TestHelper {
  static dec(val, scale) {
    let zerosCount;

    if (scale === "ether") {
      zerosCount = 18;
    } else if (scale === "finney") zerosCount = 15;
    else {
      zerosCount = scale;
    }

    const strVal = val.toString();
    const strZeros = "0".repeat(zerosCount);

    return strVal.concat(strZeros);
  }

  static squeezeAddr(address) {
    const len = address.length;
    return address
      .slice(0, 6)
      .concat("...")
      .concat(address.slice(len - 4, len));
  }

  static getDifference(x, y) {
    const x_BN = ethers.BigNumber.from(x);
    const y_BN = ethers.BigNumber.from(y);

    return Number(x_BN.sub(y_BN).abs());
  }

  static assertIsApproximatelyEqual(x, y, error = 1000) {
    assert.isAtMost(this.getDifference(x, y), error);
  }

  static zipToObject(array1, array2) {
    let obj = {};
    array1.forEach((element, idx) => (obj[element] = array2[idx]));
    return obj;
  }

  static getGasMetrics(gasCostList) {
    const minGas = Math.min(...gasCostList);
    const maxGas = Math.max(...gasCostList);

    let sum = 0;
    for (const gas of gasCostList) {
      sum += gas;
    }

    if (sum === 0) {
      return {
        gasCostList: gasCostList,
        minGas: undefined,
        maxGas: undefined,
        meanGas: undefined,
        medianGas: undefined,
      };
    }
    const meanGas = sum / gasCostList.length;

    // median is the middle element (for odd list size) or element adjacent-right of middle (for even list size)
    const sortedGasCostList = [...gasCostList].sort();
    const medianGas = sortedGasCostList[Math.floor(sortedGasCostList.length / 2)];
    return { gasCostList, minGas, maxGas, meanGas, medianGas };
  }

  static getGasMinMaxAvg(gasCostList) {
    const metrics = th.getGasMetrics(gasCostList);

    const minGas = metrics.minGas;
    const maxGas = metrics.maxGas;
    const meanGas = metrics.meanGas;
    const medianGas = metrics.medianGas;

    return { minGas, maxGas, meanGas, medianGas };
  }

  static getEndOfAccount(account) {
    const accountLast2bytes = account.slice(account.length - 4, account.length);
    return accountLast2bytes;
  }

  static randDecayFactor(min, max) {
    const max_BN = new BigNumber(max);
    const min_BN = new BigNumber(min);
    const random_BN = new BigNumber(Math.random());

    const amount_BN = random_BN.multipliedBy(max_BN.minus(min_BN)).plus(min_BN);

    const amountInWei = web3.utils.toWei(amount_BN.toFixed(18), "ether");
    return amountInWei;
  }

  static randAmountInWei(min, max) {
    const amount = Math.random() * (max - min) + min;
    const amountInWei = web3.utils.toWei(amount.toString(), "ether");
    return amountInWei;
  }

  static randAmountInGWei(min, max) {
    const amount = Math.floor(Math.random() * (max - min) + min);
    const amountInWei = web3.utils.toWei(amount.toString(), "gwei");
    return amountInWei;
  }

  static makeWei(num) {
    return web3.utils.toWei(num.toString(), "ether");
  }

  static appendData(results, message, data) {
    data.push(message + `\n`);
    for (const key in results) {
      data.push(key + "," + results[key] + "\n");
    }
  }

  static getRandICR(min, max) {
    const ICR_Percent = Math.floor(Math.random() * (max - min) + min);

    // Convert ICR to a duint
    const ICR = web3.utils.toWei((ICR_Percent * 10).toString(), "finney");
    return ICR;
  }

  static computeICR(coll, debt, price) {
    const collBN = ethers.BigNumber.from(coll);
    const debtBN = ethers.BigNumber.from(debt);
    const priceBN = ethers.BigNumber.from(price);

    const ICR = debtBN.eq(this.toBN("0"))
      ? this.toBN("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
      : collBN.mul(priceBN).div(debtBN);

    return ICR;
  }

  static async ICRbetween100and110(account, troveManager, price) {
    const ICR = await troveManager.getCurrentICR(account.address, price);
    return ICR.gt(MoneyValues._ICR100) && ICR.lt(MoneyValues._MCR);
  }

  static async isUndercollateralized(account, troveManager, price) {
    const ICR = await troveManager.getCurrentICR(account.address, price);
    return ICR.lt(MoneyValues._MCR);
  }

  static toBN(num) {
    return ethers.BigNumber.from(num);
  }

  static async gasUsed(tx) {
    const receipt = await tx.wait();
    const gas = receipt.gasUsed;
    return gas;
  }

  static applyLiquidationFee(ethAmount) {
    return ethAmount.mul(this.toBN(this.dec(995, 15))).div(MoneyValues._1e18BN);
  }
  // --- Logging functions ---

  static logGasMetrics(gasResults, message) {
    console.log(
      `\n ${message} \n
      min gas: ${gasResults.minGas} \n
      max gas: ${gasResults.maxGas} \n
      mean gas: ${gasResults.meanGas} \n
      median gas: ${gasResults.medianGas} \n`,
    );
  }

  static logAllGasCosts(gasResults) {
    console.log(`all gas costs: ${gasResults.gasCostList} \n`);
  }

  static logGas(gas, message) {
    console.log(
      `\n ${message} \n
      gas used: ${gas} \n`,
    );
  }

  static async logActiveAccounts(contracts, n) {
    const count = await contracts.sortedTroves.getSize();
    const price = await contracts.priceFeedTestnet.getPrice();

    n = typeof n === "undefined" ? count : n;

    let account = await contracts.sortedTroves.getLast();
    const head = await contracts.sortedTroves.getFirst();

    console.log(`Total active accounts: ${count}`);
    console.log(`First ${n} accounts, in ascending ICR order:`);

    let i = 0;
    while (i < n) {
      const squeezedAddr = this.squeezeAddr(account);
      const coll = (await contracts.troveManager.Troves(account.address))[1];
      const debt = (await contracts.troveManager.Troves(account.address))[0];
      const ICR = await contracts.troveManager.getCurrentICR(account.address, price);

      console.log(`Acct: ${squeezedAddr}  coll:${coll}  debt: ${debt}  ICR: ${ICR}`);

      if (account === head) {
        break;
      }

      account = await contracts.sortedTroves.getPrev(account.address);

      i++;
    }
  }

  static async logAccountsArray(accounts, troveManager, price, n) {
    const length = accounts.length;

    n = typeof n === "undefined" ? length : n;

    console.log(`Number of accounts in array: ${length}`);
    console.log(`First ${n} accounts of array:`);

    for (let i = 0; i < accounts.length; i++) {
      const account = accounts[i];

      const squeezedAddr = this.squeezeAddr(account);
      const coll = (await troveManager.Troves(account.address))[1];
      const debt = (await troveManager.Troves(account.address))[0];
      const ICR = await troveManager.getCurrentICR(account.address, price);

      console.log(`Acct: ${squeezedAddr}  coll:${coll}  debt: ${debt}  ICR: ${ICR}`);
    }
  }

  static logBN(label, x) {
    x = x.toString().padStart(18, "0");
    // TODO: thousand separators
    const integerPart = x.slice(0, x.length - 18) ? x.slice(0, x.length - 18) : "0";
    console.log(`${label}:`, integerPart + "." + x.slice(-18));
  }

  // --- TCR and Recovery Mode functions ---

  // These functions use the PriceFeedTestNet view price function getPrice() which is sufficient for testing.
  // the mainnet contract PriceFeed uses fetchPrice, which is non-view and writes to storage.

  // To checkRecoveryMode / getTCR from the protocol mainnet contracts, pass a price value - this can be the lastGoodPrice
  // stored in the protocol, or the current Chainlink FILUSD price, etc.

  static async checkRecoveryMode(contracts) {
    const price = await contracts.priceFeedTestnet.getPrice();
    return contracts.troveManager.checkRecoveryMode(price);
  }

  static async getTCR(contracts) {
    const price = await contracts.priceFeedTestnet.getPrice();
    return contracts.troveManager.getTCR(price);
  }

  // --- Gas compensation calculation functions ---

  // Given a composite debt, returns the actual debt  - i.e. subtracts the virtual debt.
  // Virtual debt = 50 DebtToken.
  static async getActualDebtFromComposite(compositeDebt, contracts) {
    const issuedDebt = await contracts.troveManager.getActualDebtFromComposite(compositeDebt);
    return issuedDebt;
  }

  // Adds the gas compensation (50 DebtToken)
  static async getCompositeDebt(contracts, debt) {
    const compositeDebt = contracts.borrowerOperations.getCompositeDebt(debt);
    return compositeDebt;
  }

  static async getTroveEntireColl(contracts, trove) {
    return this.toBN((await contracts.troveManager.getEntireDebtAndColl(trove))[1]);
  }

  static async getTroveEntireDebt(contracts, trove) {
    return this.toBN((await contracts.troveManager.getEntireDebtAndColl(trove))[0]);
  }

  static async getTroveStake(contracts, trove) {
    return contracts.troveManager.getTroveStake(trove);
  }

  /*
   * given the requested DebtToken amomunt in openTrove, returns the total debt
   * So, it adds the gas compensation and the borrowing fee
   */
  static async getOpenTroveTotalDebt(contracts, debtTokenAmount) {
    const fee = await contracts.troveManager.getBorrowingFee(debtTokenAmount);
    const compositeDebt = await this.getCompositeDebt(contracts, debtTokenAmount);
    return compositeDebt.add(fee);
  }

  /*
   * given the desired total debt, returns the DebtToken amount that needs to be requested in openTrove
   * So, it subtracts the gas compensation and then the borrowing fee
   */
  static async getOpenTroveDebtTokenAmount(contracts, totalDebt) {
    const actualDebt = await this.getActualDebtFromComposite(totalDebt, contracts);
    return this.getNetBorrowingAmount(contracts, actualDebt);
  }

  // Subtracts the borrowing fee
  static async getNetBorrowingAmount(contracts, debtWithFee) {
    const borrowingRate = await contracts.troveManager.getBorrowingRateWithDecay();
    return this.toBN(debtWithFee)
      .mul(MoneyValues._1e18BN)
      .div(MoneyValues._1e18BN.add(borrowingRate));
  }

  // Adds the borrowing fee
  static async getAmountWithBorrowingFee(contracts, debtTokenAmount) {
    const fee = await contracts.troveManager.getBorrowingFee(debtTokenAmount);
    return debtTokenAmount.add(fee);
  }

  // Adds the redemption fee
  static async getRedemptionGrossAmount(contracts, expected) {
    const redemptionRate = await contracts.troveManager.getRedemptionRate();
    return expected.mul(MoneyValues._1e18BN).div(MoneyValues._1e18BN.add(redemptionRate));
  }

  // Get's total collateral minus total gas comp, for a series of troves.
  static async getExpectedTotalCollMinusTotalGasComp(troveList, contracts) {
    let totalCollRemainder = ethers.BigNumber.from("0");

    for (const trove of troveList) {
      const remainingColl = this.getCollMinusGasComp(trove, contracts);
      totalCollRemainder = totalCollRemainder.add(remainingColl);
    }
    return totalCollRemainder;
  }

  static async getEmittedRedemptionValues(redemptionTx) {
    const receipt = await redemptionTx.wait();
    for (let i = 0; i < receipt.events.length; i++) {
      if (receipt.events[i].event === "Redemption") {
        const debtTokenAmount = receipt.events[i].args[0];
        const totalDebtTokenRedeemed = receipt.events[i].args[1];
        const totalFILDrawn = receipt.events[i].args[2];
        const FILFee = receipt.events[i].args[3];

        return [debtTokenAmount, totalDebtTokenRedeemed, totalFILDrawn, FILFee];
      }
    }
    throw "The transaction logs do not contain a redemption event";
  }

  static async getEmittedLiquidationValues(liquidationTx) {
    const receipt = await liquidationTx.wait();
    for (let i = 0; i < receipt.events.length; i++) {
      if (receipt.events[i].event === "Liquidation") {
        const liquidatedDebt = receipt.events[i].args[0];
        const liquidatedColl = receipt.events[i].args[1];
        const collGasComp = receipt.events[i].args[2];
        const debtTokenGasComp = receipt.events[i].args[3];

        return [liquidatedDebt, liquidatedColl, collGasComp, debtTokenGasComp];
      }
    }
    throw "The transaction logs do not contain a liquidation event";
  }

  static getEmittedLiquidatedDebt(liquidationTx) {
    return this.getLiquidationEventArg(liquidationTx, 0); // LiquidatedDebt is position 0 in the Liquidation event
  }

  static getEmittedLiquidatedColl(liquidationTx) {
    return this.getLiquidationEventArg(liquidationTx, 1); // LiquidatedColl is position 1 in the Liquidation event
  }

  static getEmittedGasComp(liquidationTx) {
    return this.getLiquidationEventArg(liquidationTx, 2); // GasComp is position 2 in the Liquidation event
  }

  static getLiquidationEventArg(liquidationTx, arg) {
    for (let i = 0; i < liquidationTx.logs.length; i++) {
      if (liquidationTx.logs[i].event === "Liquidation") {
        return liquidationTx.logs[i].args[arg];
      }
    }

    throw "The transaction logs do not contain a liquidation event";
  }

  static async getFeeFromDebtTokenBorrowingEvent(tx) {
    const receipt = await tx.wait();

    for (let i = 0; i < receipt.events.length; i++) {
      if (receipt.events[i].event === "DebtTokenBorrowingFeePaid") {
        return receipt.events[i].args[1].toString();
      }
    }
    throw "The transaction logs do not contain an DebtTokenBorrowingFeePaid event";
  }

  static async getEventArgByIndex(tx, eventName, argIndex) {
    const receipt = await tx.wait();

    for (let i = 0; i < receipt.events.length; i++) {
      if (receipt.events[i].event === eventName) {
        return receipt.events[i].args[argIndex];
      }
    }
    throw `The transaction logs do not contain event ${eventName}`;
  }

  static async getEventArgByName(tx, eventName, argName) {
    const receipt = await tx.wait();

    for (let i = 0; i < receipt.events.length; i++) {
      if (receipt.events[i].event === eventName) {
        const keys = Object.keys(receipt.events[i].args);
        for (let j = 0; j < keys.length; j++) {
          if (keys[j] === argName) {
            return receipt.events[i].args[keys[j]];
          }
        }
      }
    }

    throw `The transaction logs do not contain event ${eventName} and arg ${argName}`;
  }

  static async getAllEventsByName(tx, eventName) {
    const receipt = await tx.wait();
    const events = [];
    for (let i = 0; i < receipt.events.length; i++) {
      if (receipt.events[i].event === eventName) {
        events.push(receipt.events[i]);
      }
    }
    return events;
  }

  static getDebtAndCollFromTroveUpdatedEvents(troveUpdatedEvents, address) {
    const event = troveUpdatedEvents.filter((event) => event.args[0] === address)[0];
    return [event.args[1], event.args[2]];
  }

  static async getBorrowerOpsListHint(contracts, newColl, newDebt) {
    const newNICR = await contracts.hintHelpers.computeNominalCR(newColl, newDebt);
    const { hintAddress: approxfullListHint, latestRandomSeed } =
      await contracts.hintHelpers.getApproxHint(newNICR, 5, this.latestRandomSeed);
    this.latestRandomSeed = latestRandomSeed;

    const { 0: upperHint, 1: lowerHint } = await contracts.sortedTroves.findInsertPosition(
      newNICR,
      approxfullListHint,
      approxfullListHint,
    );
    return { upperHint, lowerHint };
  }

  static async getEntireCollAndDebt(contracts, account) {
    // console.log(`account: ${account}`)
    const rawColl = (await contracts.troveManager.Troves(account.address))[1];
    const rawDebt = (await contracts.troveManager.Troves(account.address))[0];
    const pendingFILReward = await contracts.troveManager.getPendingFILReward(account.address);
    const pendingDebtTokenDebtReward = await contracts.troveManager.getPendingDebtReward(
      account.address,
    );
    const entireColl = rawColl.add(pendingFILReward);
    const entireDebt = rawDebt.add(pendingDebtTokenDebtReward);

    return { entireColl, entireDebt };
  }

  static async getCollAndDebtFromAddColl(contracts, account, amount) {
    const { entireColl, entireDebt } = await this.getEntireCollAndDebt(contracts, account);

    const newColl = entireColl.add(this.toBN(amount));
    const newDebt = entireDebt;
    return { newColl, newDebt };
  }

  static async getCollAndDebtFromWithdrawColl(contracts, account, amount) {
    const { entireColl, entireDebt } = await this.getEntireCollAndDebt(contracts, account);
    // console.log(`entireColl  ${entireColl}`)
    // console.log(`entireDebt  ${entireDebt}`)

    const newColl = entireColl.sub(this.toBN(amount));
    const newDebt = entireDebt;
    return { newColl, newDebt };
  }

  static async getCollAndDebtFromWithdrawDebtToken(contracts, account, amount) {
    const fee = await contracts.troveManager.getBorrowingFee(amount);
    const { entireColl, entireDebt } = await this.getEntireCollAndDebt(contracts, account);

    const newColl = entireColl;
    const newDebt = entireDebt.add(this.toBN(amount)).add(fee);

    return { newColl, newDebt };
  }

  static async getCollAndDebtFromRepayDebtToken(contracts, account, amount) {
    const { entireColl, entireDebt } = await this.getEntireCollAndDebt(contracts, account);

    const newColl = entireColl;
    const newDebt = entireDebt.sub(this.toBN(amount));

    return { newColl, newDebt };
  }

  static async getCollAndDebtFromAdjustment(contracts, account, FILChange, debtTokenChange) {
    const { entireColl, entireDebt } = await this.getEntireCollAndDebt(contracts, account);

    // const coll = (await contracts.troveManager.Troves(account.address))[1]
    // const debt = (await contracts.troveManager.Troves(account.address))[0]

    const fee = debtTokenChange.gt(this.toBN("0"))
      ? await contracts.troveManager.getBorrowingFee(debtTokenChange)
      : this.toBN("0");
    const newColl = entireColl.add(FILChange);
    const newDebt = entireDebt.add(debtTokenChange).add(fee);

    return { newColl, newDebt };
  }

  // --- BorrowerOperations gas functions ---

  static async openTrove_allAccounts(accounts, contracts, FILAmount, debtTokenAmount) {
    const gasCostList = [];
    const totalDebt = await this.getOpenTroveTotalDebt(contracts, debtTokenAmount);

    for (const account of accounts) {
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        FILAmount,
        totalDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, debtTokenAmount, upperHint, lowerHint, { value: FILAmount });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async openTrove_allAccounts_randomFIL(
    minFIL,
    maxFIL,
    accounts,
    contracts,
    debtTokenAmount,
  ) {
    const gasCostList = [];
    const totalDebt = await this.getOpenTroveTotalDebt(contracts, debtTokenAmount);

    for (const account of accounts) {
      const randCollAmount = this.randAmountInWei(minFIL, maxFIL);
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        randCollAmount,
        totalDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, debtTokenAmount, upperHint, lowerHint, {
          value: randCollAmount,
        });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async openTrove_allAccounts_randomFIL_ProportionalDebt(
    minFIL,
    maxFIL,
    accounts,
    contracts,
    proportion,
  ) {
    const gasCostList = [];

    for (const account of accounts) {
      const randCollAmount = this.randAmountInWei(minFIL, maxFIL);
      const proportionalDebtToken = web3.utils
        .toBN(proportion)
        .mul(ethers.BigNumber.from(randCollAmount));
      const totalDebt = await this.getOpenTroveTotalDebt(contracts, proportionalDebtToken);

      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        randCollAmount,
        totalDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, proportionalDebtToken, upperHint, lowerHint, {
          value: randCollAmount,
        });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async openTrove_allAccounts_randomFIL_randomDebtToken(
    minFIL,
    maxFIL,
    accounts,
    contracts,
    minDebtTokenProportion,
    maxDebtTokenProportion,
    logging = false,
  ) {
    const gasCostList = [];
    const price = await contracts.priceFeedTestnet.getPrice();
    const _1e18 = ethers.BigNumber.from("1000000000000000000");

    let i = 0;
    for (const account of accounts) {
      const randCollAmount = this.randAmountInWei(minFIL, maxFIL);
      // console.log(`randCollAmount ${randCollAmount }`)
      const randDebtTokenProportion = this.randAmountInWei(
        minDebtTokenProportion,
        maxDebtTokenProportion,
      );
      const proportionalDebtToken = this.toBN(randDebtTokenProportion).mul(
        ethers.BigNumber.from(randCollAmount).div(_1e18),
      );
      const totalDebt = await this.getOpenTroveTotalDebt(contracts, proportionalDebtToken);
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        randCollAmount,
        totalDebt,
      );

      const feeFloor = this.dec(5, 16);
      const tx = await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, proportionalDebtToken, upperHint, lowerHint, {
          value: randCollAmount,
        });
      const receipt = await tx.wait();

      if (logging && receipt.status) {
        i++;
        const ICR = await contracts.troveManager.getCurrentICR(account.address, price);
        // console.log(`${i}. Trove opened. addr: ${this.squeezeAddr(account)} coll: ${randCollAmount} debt: ${proportionalDebtToken} ICR: ${ICR}`)
      }
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async openTrove_allAccounts_randomDebtToken(
    minDebtToken,
    maxDebtToken,
    accounts,
    contracts,
    FILAmount,
  ) {
    const gasCostList = [];

    for (const account of accounts) {
      const randDebtTokenAmount = this.randAmountInWei(minDebtToken, maxDebtToken);
      const totalDebt = await this.getOpenTroveTotalDebt(contracts, randDebtTokenAmount);
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        FILAmount,
        totalDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, randDebtTokenAmount, upperHint, lowerHint, {
          value: FILAmount,
        });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async closeTrove_allAccounts(accounts, contracts) {
    const gasCostList = [];

    for (const account of accounts) {
      const tx = await contracts.borrowerOperations.connect(account).closeTrove();
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async openTrove_allAccounts_decreasingDebtTokenAmounts(
    accounts,
    contracts,
    FILAmount,
    maxDebtTokenAmount,
  ) {
    const gasCostList = [];

    let i = 0;
    for (const account of accounts) {
      const debtTokenAmount = (maxDebtTokenAmount - i).toString();
      const debtTokenAmountWei = web3.utils.toWei(debtTokenAmount, "ether");
      const totalDebt = await this.getOpenTroveTotalDebt(contracts, debtTokenAmountWei);
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        FILAmount,
        totalDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, debtTokenAmountWei, upperHint, lowerHint, {
          value: FILAmount,
        });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
      i += 1;
    }
    return this.getGasMetrics(gasCostList);
  }

  static async openTrove(
    contracts,
    { maxFeePercentage, extraDebtTokenAmount, upperHint, lowerHint, ICR, extraParams },
  ) {
    if (!maxFeePercentage) maxFeePercentage = this._100pct;
    if (!extraDebtTokenAmount) extraDebtTokenAmount = this.toBN(0);
    else if (typeof extraDebtTokenAmount === "string")
      extraDebtTokenAmount = this.toBN(extraDebtTokenAmount);
    if (!upperHint) upperHint = this.ZERO_ADDRESS;
    if (!lowerHint) lowerHint = this.ZERO_ADDRESS;

    const MIN_DEBT = (
      await this.getNetBorrowingAmount(contracts, await contracts.borrowerOperations.MIN_NET_DEBT())
    ).add(this.toBN(1)); // add 1 to avoid rounding issues
    const debtTokenAmount = MIN_DEBT.add(extraDebtTokenAmount);

    if (!ICR && !extraParams.value)
      ICR = this.toBN(this.dec(15, 17)); // 150%
    else if (typeof ICR === "string") ICR = this.toBN(ICR);

    const totalDebt = await this.getOpenTroveTotalDebt(contracts, debtTokenAmount);
    const netDebt = await this.getActualDebtFromComposite(totalDebt, contracts);

    if (ICR) {
      const price = await contracts.priceFeedTestnet.getPrice();
      extraParams.value = ICR.mul(totalDebt).div(price);
    }

    const contract = extraParams.from
      ? contracts.borrowerOperations.connect(extraParams.from)
      : contracts.borrowerOperations;
    const tx = await contract.openTrove(
      maxFeePercentage,
      debtTokenAmount.toString(),
      upperHint,
      lowerHint,
      {
        value: extraParams.value,
      },
    );

    return {
      debtTokenAmount,
      netDebt,
      totalDebt,
      ICR,
      collateral: extraParams.value,
      tx,
    };
  }

  static async withdrawDebtToken(
    contracts,
    { maxFeePercentage, debtTokenAmount, ICR, upperHint, lowerHint, extraParams },
  ) {
    if (!maxFeePercentage) maxFeePercentage = this._100pct;
    if (!upperHint) upperHint = this.ZERO_ADDRESS;
    if (!lowerHint) lowerHint = this.ZERO_ADDRESS;

    assert(
      !(debtTokenAmount && ICR) && (debtTokenAmount || ICR),
      "Specify either debt token amount or target ICR, but not both",
    );

    let increasedTotalDebt;
    if (ICR) {
      assert(extraParams.from, "A from account is needed");
      const { debt, coll } = await contracts.troveManager.getEntireDebtAndColl(
        extraParams.from.address,
      );
      const price = await contracts.priceFeedTestnet.getPrice();
      const targetDebt = coll.mul(price).div(ICR);
      assert(targetDebt > debt, "ICR is already greater than or equal to target");
      increasedTotalDebt = targetDebt.sub(debt);
      debtTokenAmount = await this.getNetBorrowingAmount(contracts, increasedTotalDebt);
    } else {
      increasedTotalDebt = await this.getAmountWithBorrowingFee(contracts, debtTokenAmount);
    }

    const contract = extraParams.from
      ? contracts.borrowerOperations.connect(extraParams.from)
      : contracts.borrowerOperations;
    await contract.withdrawDebtToken(maxFeePercentage, debtTokenAmount, upperHint, lowerHint, {
      value: extraParams.value,
    });

    return {
      debtTokenAmount,
      increasedTotalDebt,
    };
  }

  static async adjustTrove_allAccounts(accounts, contracts, FILAmount, debtTokenAmount) {
    const gasCostList = [];

    for (const account of accounts) {
      let tx;

      let FILChangeBN = this.toBN(FILAmount);
      let debtTokenChangeBN = this.toBN(debtTokenAmount);

      const { newColl, newDebt } = await this.getCollAndDebtFromAdjustment(
        contracts,
        account,
        FILChangeBN,
        debtTokenChangeBN,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const zero = this.toBN("0");

      let isDebtIncrease = debtTokenChangeBN.gt(zero);
      debtTokenChangeBN = debtTokenChangeBN.abs();

      // Add FIL to trove
      if (FILChangeBN.gt(zero)) {
        tx = await contracts.borrowerOperations
          .connect(account)
          .adjustTrove(this._100pct, 0, debtTokenChangeBN, isDebtIncrease, upperHint, lowerHint, {
            value: FILChangeBN,
          });
        // Withdraw FIL from trove
      } else if (FILChangeBN.lt(zero)) {
        FILChangeBN = FILChangeBN.neg();
        tx = await contracts.borrowerOperations
          .connect(account)
          .adjustTrove(
            this._100pct,
            FILChangeBN,
            debtTokenChangeBN,
            isDebtIncrease,
            upperHint,
            lowerHint,
          );
      }

      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async adjustTrove_allAccounts_randomAmount(
    accounts,
    contracts,
    FILMin,
    FILMax,
    debtTokenMin,
    debtTokenMax,
  ) {
    const gasCostList = [];

    for (const account of accounts) {
      let tx;

      let FILChangeBN = this.toBN(this.randAmountInWei(FILMin, FILMax));
      let debtTokenChangeBN = this.toBN(this.randAmountInWei(debtTokenMin, debtTokenMax));

      const { newColl, newDebt } = await this.getCollAndDebtFromAdjustment(
        contracts,
        account,
        FILChangeBN,
        debtTokenChangeBN,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const zero = this.toBN("0");

      let isDebtIncrease = debtTokenChangeBN.gt(zero);
      debtTokenChangeBN = debtTokenChangeBN.abs();

      // Add FIL to trove
      if (FILChangeBN.gt(zero)) {
        tx = await contracts.borrowerOperations
          .connect(account)
          .adjustTrove(this._100pct, 0, debtTokenChangeBN, isDebtIncrease, upperHint, lowerHint, {
            value: FILChangeBN,
          });
        // Withdraw FIL from trove
      } else if (FILChangeBN.lt(zero)) {
        FILChangeBN = FILChangeBN.neg();
        tx = await contracts.borrowerOperations
          .connect(account)
          .adjustTrove(
            this._100pct,
            FILChangeBN,
            debtTokenChangeBN,
            isDebtIncrease,
            lowerHint,
            upperHint,
          );
      }

      const gas = await this.gasUsed(tx);
      // console.log(`FIL change: ${FILChangeBN},  Debt Token Change: ${debtTokenChangeBN}, gas: ${gas} `)

      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async addColl_allAccounts(accounts, contracts, amount) {
    const gasCostList = [];
    for (const account of accounts) {
      const { newColl, newDebt } = await this.getCollAndDebtFromAddColl(contracts, account, amount);
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations.connect(account).addColl(upperHint, lowerHint, {
        value: amount,
      });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async addColl_allAccounts_randomAmount(min, max, accounts, contracts) {
    const gasCostList = [];
    for (const account of accounts) {
      const randCollAmount = this.randAmountInWei(min, max);

      const { newColl, newDebt } = await this.getCollAndDebtFromAddColl(
        contracts,
        account,
        randCollAmount,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations.connect(account).addColl(upperHint, lowerHint, {
        value: randCollAmount,
      });
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawColl_allAccounts(accounts, contracts, amount) {
    const gasCostList = [];
    for (const account of accounts) {
      const { newColl, newDebt } = await this.getCollAndDebtFromWithdrawColl(
        contracts,
        account,
        amount,
      );
      // console.log(`newColl: ${newColl} `)
      // console.log(`newDebt: ${newDebt} `)
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .withdrawColl(amount, upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawColl_allAccounts_randomAmount(min, max, accounts, contracts) {
    const gasCostList = [];

    for (const account of accounts) {
      const randCollAmount = this.randAmountInWei(min, max);

      const { newColl, newDebt } = await this.getCollAndDebtFromWithdrawColl(
        contracts,
        account,
        randCollAmount,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .withdrawColl(randCollAmount, upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
      // console.log("gasCostlist length is " + gasCostList.length)
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawDebtToken_allAccounts(accounts, contracts, amount) {
    const gasCostList = [];

    for (const account of accounts) {
      const { newColl, newDebt } = await this.getCollAndDebtFromWithdrawDebtToken(
        contracts,
        account,
        amount,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .withdrawDebtToken(this._100pct, amount, upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawDebtToken_allAccounts_randomAmount(min, max, accounts, contracts) {
    const gasCostList = [];

    for (const account of accounts) {
      const randDebtTokenAmount = this.randAmountInWei(min, max);

      const { newColl, newDebt } = await this.getCollAndDebtFromWithdrawDebtToken(
        contracts,
        account,
        randDebtTokenAmount,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .withdrawDebtToken(this._100pct, randDebtTokenAmount, upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async repayDebtToken_allAccounts(accounts, contracts, amount) {
    const gasCostList = [];

    for (const account of accounts) {
      const { newColl, newDebt } = await this.getCollAndDebtFromRepayDebtToken(
        contracts,
        account,
        amount,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .repayDebtToken(amount, upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async repayDebtToken_allAccounts_randomAmount(min, max, accounts, contracts) {
    const gasCostList = [];

    for (const account of accounts) {
      const randDebtTokenAmount = this.randAmountInWei(min, max);

      const { newColl, newDebt } = await this.getCollAndDebtFromRepayDebtToken(
        contracts,
        account,
        randDebtTokenAmount,
      );
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        newDebt,
      );

      const tx = await contracts.borrowerOperations
        .connect(account)
        .repayDebtToken(randDebtTokenAmount, upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async getCurrentICR_allAccounts(accounts, contracts, functionCaller) {
    const gasCostList = [];
    const price = await contracts.priceFeedTestnet.getPrice();

    for (const account of accounts) {
      const tx = await functionCaller.troveManager_getCurrentICR(account.address, price);
      const gas = (await this.gasUsed(tx)) - 21000;
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  // --- Redemption functions ---

  static async redeemCollateral(
    redeemer,
    contracts,
    debtTokenAmount,
    gasPrice = 0,
    maxFee = this._100pct,
  ) {
    const price = await contracts.priceFeedTestnet.getPrice();
    const tx = await this.performRedemptionTx(
      redeemer,
      price,
      contracts,
      debtTokenAmount,
      maxFee,
      gasPrice,
    );
    const gas = await this.gasUsed(tx);
    return gas;
  }

  static async redeemCollateralAndGetTxObject(
    redeemer,
    contracts,
    debtTokenAmount,
    gasPrice,
    maxFee = this._100pct,
  ) {
    // console.log("GAS PRICE:  " + gasPrice)
    if (gasPrice === undefined) {
      gasPrice = 0;
    }
    const price = await contracts.priceFeedTestnet.getPrice();
    const tx = await this.performRedemptionTx(
      redeemer,
      price,
      contracts,
      debtTokenAmount,
      maxFee,
      gasPrice,
    );
    return tx;
  }

  static async redeemCollateral_allAccounts_randomAmount(min, max, accounts, contracts) {
    const gasCostList = [];
    const price = await contracts.priceFeedTestnet.getPrice();

    for (const redeemer of accounts) {
      const randDebtTokenAmount = this.randAmountInWei(min, max);

      await this.performRedemptionTx(redeemer, price, contracts, randDebtTokenAmount);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async performRedemptionTx(
    redeemer,
    price,
    contracts,
    debtTokenAmount,
    maxFee = 0,
    gasPrice_toUse = 0,
  ) {
    const redemptionhint = await contracts.hintHelpers.getRedemptionHints(
      debtTokenAmount,
      price,
      gasPrice_toUse,
    );

    const firstRedemptionHint = redemptionhint[0];
    const partialRedemptionNewICR = redemptionhint[1];

    const { hintAddress: approxPartialRedemptionHint, latestRandomSeed } =
      await contracts.hintHelpers.getApproxHint(partialRedemptionNewICR, 50, this.latestRandomSeed);
    this.latestRandomSeed = latestRandomSeed;

    const exactPartialRedemptionHint = await contracts.sortedTroves.findInsertPosition(
      partialRedemptionNewICR,
      approxPartialRedemptionHint,
      approxPartialRedemptionHint,
    );

    const tx = await contracts.troveManager
      .connect(redeemer)
      .redeemCollateral(
        debtTokenAmount,
        firstRedemptionHint,
        exactPartialRedemptionHint[0],
        exactPartialRedemptionHint[1],
        partialRedemptionNewICR,
        0,
        maxFee,
        { gasPrice: gasPrice_toUse },
      );

    return tx;
  }

  // --- Composite functions ---

  static async makeTrovesIncreasingICR(accounts, contracts) {
    let amountFinney = 2000;

    for (const account of accounts) {
      const coll = web3.utils.toWei(amountFinney.toString(), "finney");

      await contracts.borrowerOperations
        .connect(account)
        .openTrove(this._100pct, "200000000000000000000", account.address, account.address, {
          value: coll,
        });

      amountFinney += 10;
    }
  }

  // --- StabilityPool gas functions ---

  static async provideToSP_allAccounts(accounts, stabilityPool, amount) {
    const gasCostList = [];
    for (const account of accounts) {
      const tx = await stabilityPool.connect(account).provideToSP(amount, this.ZERO_ADDRESS);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async provideToSP_allAccounts_randomAmount(min, max, accounts, stabilityPool) {
    const gasCostList = [];
    for (const account of accounts) {
      const randomDebtTokenAmount = this.randAmountInWei(min, max);
      const tx = await stabilityPool
        .connect(account)
        .provideToSP(randomDebtTokenAmount, this.ZERO_ADDRESS);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawFromSP_allAccounts(accounts, stabilityPool, amount) {
    const gasCostList = [];
    for (const account of accounts) {
      const tx = await stabilityPool.connect(account).withdrawFromSP(amount);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawFromSP_allAccounts_randomAmount(min, max, accounts, stabilityPool) {
    const gasCostList = [];
    for (const account of accounts) {
      const randomDebtTokenAmount = this.randAmountInWei(min, max);
      const tx = await stabilityPool.connect(account).withdrawFromSP(randomDebtTokenAmount);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  static async withdrawFILGainToTrove_allAccounts(accounts, contracts) {
    const gasCostList = [];
    for (const account of accounts) {
      let { entireColl, entireDebt } = await this.getEntireCollAndDebt(contracts, account);
      console.log(`entireColl: ${entireColl}`);
      console.log(`entireDebt: ${entireDebt}`);
      const FILGain = await contracts.stabilityPool.getDepositorFILGain(account.address);
      const newColl = entireColl.add(FILGain);
      const { upperHint, lowerHint } = await this.getBorrowerOpsListHint(
        contracts,
        newColl,
        entireDebt,
      );

      const tx = await contracts.stabilityPool
        .connect(account)
        .withdrawFILGainToTrove(upperHint, lowerHint);
      const gas = await this.gasUsed(tx);
      gasCostList.push(gas);
    }
    return this.getGasMetrics(gasCostList);
  }

  // --- ProtocolToken & Lockup Contract functions ---

  static async getLCAddressFromDeploymentTx(deployedLCTx) {
    const receipt = await deployedLCTx.wait();
    return receipt.events[1].args[0];
  }

  static async getLCFromDeploymentTx(deployedLCTx) {
    const deployedLCAddress = this.getLCAddressFromDeploymentTx(deployedLCTx); // grab addr of deployed contract from event
    const LC = await this.getLCFromAddress(deployedLCAddress);
    return LC;
  }

  static async getLCFromAddress(LCAddress) {
    return ethers.getContractAt("LockupContract", LCAddress);
  }

  static async registerFrontEnds(frontEnds, stabilityPool) {
    for (const frontEnd of frontEnds) {
      await stabilityPool.connect(frontEnd).registerFrontEnd(this.dec(5, 17)); // default kickback rate of 50%
    }
  }

  // --- Time functions ---

  static async fastForwardTime(seconds, currentWeb3Provider) {
    await ethers.provider.send("evm_increaseTime", [seconds]);
    await ethers.provider.send("evm_mine", []);
  }

  static async getLatestBlockTimestamp(web3Instance) {
    const blockNumber = await web3Instance.eth.getBlockNumber();
    const block = await web3Instance.eth.getBlock(blockNumber);

    return block.timestamp;
  }

  static async getTimestampFromTx(tx, web3Instance) {
    const receipt = await tx.wait();
    return this.getTimestampFromTxReceipt(receipt, web3Instance);
  }

  static async getTimestampFromTxReceipt(txReceipt, web3Instance) {
    const block = await web3Instance.eth.getBlock(txReceipt.blockNumber);
    return block.timestamp;
  }

  static secondsToDays(seconds) {
    return Number(seconds) / (60 * 60 * 24);
  }

  static daysToSeconds(days) {
    return Number(days) * (60 * 60 * 24);
  }

  static async getTimeFromAllocation(protocolToken, timePassedSinceDeployment) {
    const allocationTime = await protocolToken.getAllocationStartTime();
    return this.toBN(allocationTime).add(this.toBN(timePassedSinceDeployment));
  }

  // --- Assert functions ---

  static async assertRevert(txPromise, message = undefined) {
    try {
      const tx = await txPromise;
      // console.log("tx succeeded")
      const receipt = await tx.wait();
      assert.equal(receipt.status, 0); // when this assert fails, the expected revert didn't occur, i.e. the tx succeeded
    } catch (err) {
      // console.log("tx failed")
      assert.include(err.message, "revert");
      // TODO !!!

      // if (message) {
      //   assert.include(err.message, message)
      // }
    }
  }

  static async assertRevertWithoutAutomine(tx, message) {
    try {
      const receipt = await tx.wait();
      assert.equal(receipt.status, 0); // when this assert fails, the expected revert didn't occur, i.e. the tx succeeded
    } catch (error) {
      const revertReason = await getRevertReason(error?.transactionHash);
      assert.equal(revertReason, message);
    }
  }

  static async assertAssert(txPromise) {
    try {
      const tx = await txPromise;
      assert.isFalse(tx.receipt.status); // when this assert fails, the expected revert didn't occur, i.e. the tx succeeded
    } catch (err) {
      assert.include(err.message, "invalid opcode");
    }
  }

  // --- Misc. functions  ---

  static async forceSendEth(from, receiver, value) {
    const destructibleFactory = await ethers.getContractFactory("Destructible");
    const destructible = await destructibleFactory.deploy();
    await web3.eth.sendTransaction({ to: destructible.address, from, value });
    await destructible.destruct(receiver);
  }

  static hexToParam(hexValue) {
    return ("0".repeat(64) + hexValue.slice(2)).slice(-64);
  }

  static formatParam(param) {
    let formattedParam = param;
    if (
      typeof param === "number" ||
      typeof param === "object" ||
      (typeof param === "string" && new RegExp("[0-9]*").test(param))
    ) {
      formattedParam = web3.utils.toHex(formattedParam);
    } else if (typeof param === "boolean") {
      formattedParam = param ? "0x01" : "0x00";
    } else if (param.slice(0, 2) !== "0x") {
      formattedParam = web3.utils.asciiToHex(formattedParam);
    }

    return this.hexToParam(formattedParam);
  }
  static getTransactionData(signatureString, params) {
    /*
     console.log('signatureString: ', signatureString)
     console.log('params: ', params)
     console.log('params: ', params.map(p => typeof p))
     */
    return (
      web3.utils.sha3(signatureString).slice(0, 10) +
      params.reduce((acc, p) => acc + this.formatParam(p), "")
    );
  }
}

TestHelper.ZERO_ADDRESS = "0x" + "0".repeat(40);
TestHelper.maxBytes32 = "0x" + "f".repeat(64);
TestHelper._100pct = "1000000000000000000";
TestHelper.latestRandomSeed = 31337;
TestHelper.GAS_COMPENSATION = TestHelper.dec(200, 18);
TestHelper.MIN_NET_DEBT = TestHelper.dec(1800, 18);
TestHelper.PRICE_FEED_TIMEOUT = 4 * 60 * 60; // 4 hours

module.exports = {
  TestHelper,
  MoneyValues,
  TimeValues,
};
