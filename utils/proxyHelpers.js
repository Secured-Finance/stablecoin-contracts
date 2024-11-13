const { TestHelper: th } = require("../utils/testHelpers.js");

const buildUserProxies = async (users) => {
  const proxies = {};
  const dsProxyFactoryFactory = await ethers.getContractFactory("DSProxyFactory");
  const proxyFactory = await dsProxyFactoryFactory.deploy();

  for (let user of users) {
    const proxyTx = await proxyFactory.connect(user)["build()"]();
    const receipt = await proxyTx.wait();
    proxies[user.address] = await ethers.getContractAt("DSProxy", receipt.events[2].args.proxy);
  }

  return proxies;
};

class Proxy {
  constructor(owner, proxies, scriptAddress, contract, from = undefined) {
    this.owner = owner;
    this.proxies = proxies;
    this.scriptAddress = scriptAddress;
    this.contract = contract;
    if (contract) this.address = contract.address;
    this.from = from;
  }

  connect(user) {
    this.from = user;
    return this;
  }

  getFrom() {
    return this.from || this.owner;
  }

  getOptionalParams(params) {
    if (params.length === 0) return undefined;

    const lastParam = params[params.length - 1];
    if (typeof lastParam !== "object") return undefined;

    return lastParam;
  }

  getProxyAddressFromUser(user) {
    return this.proxies[user] ? this.proxies[user].address : user;
  }

  getProxyFromUser(user) {
    return this.proxies[user];
  }

  getProxyFromParams() {
    const user = this.getFrom();
    return this.proxies[user.address];
  }

  getSlicedParams(params) {
    if (params.length === 0) return params;
    let lastParam = params[params.length - 1];
    if (lastParam.from || lastParam.value) {
      return params.slice(0, -1);
    }

    return params;
  }

  async forwardFunction(params, signature) {
    const proxy = this.getProxyFromParams();
    if (!proxy) {
      return this.proxyFunction(signature.slice(0, signature.indexOf("(")), params);
    }
    const optionalParams = this.getOptionalParams(params);
    const calldata = th.getTransactionData(signature, this.getSlicedParams(params));
    // console.log('proxy: ', proxy.address)
    // console.log(this.scriptAddress, calldata, optionalParams)
    const executionParams = [this.scriptAddress, calldata];
    if (optionalParams) {
      executionParams.push(optionalParams);
    }

    return proxy.connect(this.getFrom())["execute(address,bytes)"](...executionParams);
  }

  async proxyFunctionWithUser(functionName, user) {
    return this.contract[functionName](this.getProxyAddressFromUser(user));
  }

  async proxyFunction(functionName, params) {
    // console.log('contract: ', this.contract.address)
    // console.log('functionName: ', functionName)
    // console.log('params: ', params)
    return this.contract[functionName](...params);
  }
}

class BorrowerOperationsProxy extends Proxy {
  constructor(owner, proxies, borrowerOperationsScriptAddress, borrowerOperations) {
    super(owner, proxies, borrowerOperationsScriptAddress, borrowerOperations);
  }

  async openTrove(...params) {
    return this.forwardFunction(params, "openTrove(uint256,uint256,address,address)");
  }

  async addColl(...params) {
    return this.forwardFunction(params, "addColl(address,address)");
  }

  async withdrawColl(...params) {
    return this.forwardFunction(params, "withdrawColl(uint256,address,address)");
  }

  async withdrawDebtToken(...params) {
    return this.forwardFunction(params, "withdrawDebtToken(uint256,uint256,address,address)");
  }

  async repayDebtToken(...params) {
    return this.forwardFunction(params, "repayDebtToken(uint256,address,address)");
  }

  async closeTrove(...params) {
    return this.forwardFunction(params, "closeTrove()");
  }

  async adjustTrove(...params) {
    return this.forwardFunction(
      params,
      "adjustTrove(uint256,uint256,uint256,bool,address,address)",
    );
  }

  async claimRedeemedCollateral(...params) {
    return this.forwardFunction(params, "claimRedeemedCollateral(address)");
  }

  async getNewTCRFromTroveChange(...params) {
    return this.proxyFunction("getNewTCRFromTroveChange", params);
  }

  async getNewICRFromTroveChange(...params) {
    return this.proxyFunction("getNewICRFromTroveChange", params);
  }

  async getCompositeDebt(...params) {
    return this.proxyFunction("getCompositeDebt", params);
  }

  async GAS_COMPENSATION(...params) {
    return this.proxyFunction("GAS_COMPENSATION", params);
  }

  async MIN_NET_DEBT(...params) {
    return this.proxyFunction("MIN_NET_DEBT", params);
  }

  async BORROWING_FEE_FLOOR(...params) {
    return this.proxyFunction("BORROWING_FEE_FLOOR", params);
  }
}

class BorrowerWrappersProxy extends Proxy {
  constructor(owner, proxies, borrowerWrappersScriptAddress) {
    super(owner, proxies, borrowerWrappersScriptAddress, null);
  }

  async claimCollateralAndOpenTrove(...params) {
    return this.forwardFunction(
      params,
      "claimCollateralAndOpenTrove(uint256,uint256,address,address)",
    );
  }

  async claimSPRewardsAndRecycle(...params) {
    return this.forwardFunction(params, "claimSPRewardsAndRecycle(uint256,address,address)");
  }

  async claimStakingGainsAndRecycle(...params) {
    return this.forwardFunction(params, "claimStakingGainsAndRecycle(uint256,address,address)");
  }

  async transferFIL(...params) {
    return this.forwardFunction(params, "transferFIL(address,uint256)");
  }
}

class TroveManagerProxy extends Proxy {
  constructor(owner, proxies, troveManagerScriptAddress, troveManager) {
    super(owner, proxies, troveManagerScriptAddress, troveManager);
  }

  async Troves(user) {
    return this.proxyFunctionWithUser("Troves", user);
  }

  async getTroveStatus(user) {
    return this.proxyFunctionWithUser("getTroveStatus", user);
  }

  async getTroveDebt(user) {
    return this.proxyFunctionWithUser("getTroveDebt", user);
  }

  async getTroveColl(user) {
    return this.proxyFunctionWithUser("getTroveColl", user);
  }

  async totalStakes() {
    return this.proxyFunction("totalStakes", []);
  }

  async getPendingFILReward(...params) {
    return this.proxyFunction("getPendingFILReward", params);
  }

  async getPendingDebtReward(...params) {
    return this.proxyFunction("getPendingDebtReward", params);
  }

  async liquidate(user) {
    return this.proxyFunctionWithUser("liquidate", user);
  }

  async getTCR(...params) {
    return this.proxyFunction("getTCR", params);
  }

  async getCurrentICR(user, price) {
    return this.contract.getCurrentICR(this.getProxyAddressFromUser(user), price);
  }

  async checkRecoveryMode(...params) {
    return this.proxyFunction("checkRecoveryMode", params);
  }

  async getTroveOwnersCount() {
    return this.proxyFunction("getTroveOwnersCount", []);
  }

  async baseRate() {
    return this.proxyFunction("baseRate", []);
  }

  async L_FIL() {
    return this.proxyFunction("L_FIL", []);
  }

  async L_Debt() {
    return this.proxyFunction("L_Debt", []);
  }

  async rewardSnapshots(user) {
    return this.proxyFunctionWithUser("rewardSnapshots", user);
  }

  async lastFeeOperationTime() {
    return this.proxyFunction("lastFeeOperationTime", []);
  }

  async redeemCollateral(...params) {
    return this.forwardFunction(
      params,
      "redeemCollateral(uint256,address,address,address,uint256,uint256,uint256)",
    );
  }

  async getActualDebtFromComposite(...params) {
    return this.proxyFunction("getActualDebtFromComposite", params);
  }

  async getRedemptionFeeWithDecay(...params) {
    return this.proxyFunction("getRedemptionFeeWithDecay", params);
  }

  async getBorrowingRate() {
    return this.proxyFunction("getBorrowingRate", []);
  }

  async getBorrowingRateWithDecay() {
    return this.proxyFunction("getBorrowingRateWithDecay", []);
  }

  async getBorrowingFee(...params) {
    return this.proxyFunction("getBorrowingFee", params);
  }

  async getBorrowingFeeWithDecay(...params) {
    return this.proxyFunction("getBorrowingFeeWithDecay", params);
  }

  async getEntireDebtAndColl(...params) {
    return this.proxyFunction("getEntireDebtAndColl", params);
  }
}

class StabilityPoolProxy extends Proxy {
  constructor(owner, proxies, stabilityPoolScriptAddress, stabilityPool) {
    super(owner, proxies, stabilityPoolScriptAddress, stabilityPool);
  }

  async provideToSP(...params) {
    return this.forwardFunction(params, "provideToSP(uint256,address)");
  }

  async getCompoundedDebtTokenDeposit(user) {
    return this.proxyFunctionWithUser("getCompoundedDebtTokenDeposit", user);
  }

  async deposits(user) {
    return this.proxyFunctionWithUser("deposits", user);
  }

  async getDepositorFILGain(user) {
    return this.proxyFunctionWithUser("getDepositorFILGain", user);
  }
}

class SortedTrovesProxy extends Proxy {
  constructor(owner, proxies, sortedTroves) {
    super(owner, proxies, null, sortedTroves);
  }

  async contains(user) {
    return this.proxyFunctionWithUser("contains", user);
  }

  async isEmpty(user) {
    return this.proxyFunctionWithUser("isEmpty", user);
  }

  async findInsertPosition(...params) {
    return this.proxyFunction("findInsertPosition", params);
  }
}

class TokenProxy extends Proxy {
  constructor(owner, proxies, tokenScriptAddress, token) {
    super(owner, proxies, tokenScriptAddress, token);
  }

  async transfer(...params) {
    // switch destination to proxy if any
    params[0] = this.getProxyAddressFromUser(params[0]);
    return this.forwardFunction(params, "transfer(address,uint256)");
  }

  async transferFrom(...params) {
    // switch to proxies if any
    params[0] = this.getProxyAddressFromUser(params[0]);
    params[1] = this.getProxyAddressFromUser(params[1]);
    return this.forwardFunction(params, "transferFrom(address,address,uint256)");
  }

  async approve(...params) {
    // switch destination to proxy if any
    params[0] = this.getProxyAddressFromUser(params[0]);
    return this.forwardFunction(params, "approve(address,uint256)");
  }

  async totalSupply(...params) {
    return this.proxyFunction("totalSupply", params);
  }

  async balanceOf(user) {
    return this.proxyFunctionWithUser("balanceOf", user);
  }

  async allowance(...params) {
    // switch to proxies if any
    const owner = this.getProxyAddressFromUser(params[0]);
    const spender = this.getProxyAddressFromUser(params[1]);

    return this.proxyFunction("allowance", [owner, spender]);
  }

  async name(...params) {
    return this.proxyFunction("name", params);
  }

  async symbol(...params) {
    return this.proxyFunction("symbol", params);
  }

  async decimals(...params) {
    return this.proxyFunction("decimals", params);
  }
}

class ProtocolTokenStakingProxy extends Proxy {
  constructor(owner, proxies, tokenScriptAddress, token) {
    super(owner, proxies, tokenScriptAddress, token);
  }

  async stake(...params) {
    return this.forwardFunction(params, "stake(uint256)");
  }

  async stakes(user) {
    return this.proxyFunctionWithUser("stakes", user);
  }

  async F_DebtTOken(user) {
    return this.proxyFunctionWithUser("F_DebtTOken", user);
  }
}

module.exports = {
  buildUserProxies,
  BorrowerOperationsProxy,
  BorrowerWrappersProxy,
  TroveManagerProxy,
  StabilityPoolProxy,
  SortedTrovesProxy,
  TokenProxy,
  ProtocolTokenStakingProxy,
};
