import type { Contract } from "@ethersproject/contracts";
import { expect } from "chai";
import hre from "hardhat";
import { AbiCoder, concat, parseEther, keccak256, BaseContract } from "ethers";
import { Provider, Wallet, utils } from "zksync-ethers";

import {
  deployAccount,
  deployBatchCaller,
  deployImplementation,
  deployMockDKIMRegsitry,
  deployMockGroth16Verifier,
  deployEmailRecoveryModule,
  deployRegistry,
  deployTeeValidator,
  deployVerifier,
  deployFactory,
} from "../test/utils/deploy";
import { encodePublicKey, genKey } from "../test/utils/p256";
import { prepareTeeTx } from "../test/utils/transaction";

type DeployFunction<T extends BaseContract> = (
  wallet: Wallet,
  ...args: any
) => Promise<T>;

const deployAndWait = async <T extends BaseContract>(
  wallet: Wallet,
  deployFunction: DeployFunction<T>,
  args: Array<any>
): Promise<T> => {
  const nonce = await getNonce(wallet);
  const deployedContract = await deployFunction(wallet, ...args);
  await waitTillNonceUpdate(wallet, nonce);
  return deployedContract;
};

const executeAndWait = async (
  wallet: Wallet,
  func: (args?: any) => Promise<any>,
  args: Array<any>
) => {
  const nonce = await getNonce(wallet);
  await func(...args);
  await waitTillNonceUpdate(wallet, nonce);
};

const main = async () => {
  const privateKey = process.env.PRIVATE_KEY!;

  // @ts-ignore
  const provider = new Provider(hre.network.config.url);
  const richWallet = new Wallet(privateKey, provider);

  const keyPair = genKey();
  const publicKey = encodePublicKey(keyPair);

  const batchCaller = await deployAndWait(richWallet, deployBatchCaller, []);
  const verifier = await deployAndWait(richWallet, deployVerifier, []);
  const teeValidator = await deployAndWait(richWallet, deployTeeValidator, [
    await verifier.getAddress(),
  ]);
  const implementation = await deployAndWait(richWallet, deployImplementation, [
    await batchCaller.getAddress(),
  ]);
  const registry = await deployAndWait(richWallet, deployRegistry, []);
  const factory = await deployAndWait(richWallet, deployFactory, [
    await implementation.getAddress(),
    await registry.getAddress(),
  ]);

  await executeAndWait(
    richWallet,
    async (factoryAddress) => registry.setFactory(factoryAddress),
    [await factory.getAddress()]
  );

  const account = await deployAndWait(richWallet, deployAccount, [
    await richWallet.getNonce(),
    factory,
    await teeValidator.getAddress(),
    publicKey,
  ]);
  const accountAddress = await account.getAddress();

  // 0.005 ETH transfered to Account
  await executeAndWait(
    richWallet,
    async () =>
      await (
        await richWallet.sendTransaction({
          to: accountAddress,
          value: parseEther("0.005"),
        })
      ).wait(),
    []
  );

  // deploy recovery module

  const mockVerifier = await deployAndWait(
    richWallet,
    deployMockGroth16Verifier,
    []
  );

  const defaultDkimRegistry = await deployAndWait(
    richWallet,
    deployMockDKIMRegsitry,
    []
  );

  const recoveryModule = await deployAndWait(
    richWallet,
    deployEmailRecoveryModule,
    [mockVerifier, defaultDkimRegistry]
  );

  const recoveryModuleAddress = await recoveryModule.getAddress();

  expect(await account.isModule(recoveryModuleAddress)).to.be.false;

  // init module
  const timeLock = 2;
  const threshold = 1;
  const abiCoder = AbiCoder.defaultAbiCoder();
  const guardianHash = keccak256(
    abiCoder.encode(["string"], ["mockGuardianHash"])
  );
  const guardianHashes = [guardianHash];

  const initData = abiCoder.encode(
    ["uint128", "uint128", "bytes32[]"],
    [timeLock, threshold, guardianHashes]
  );
  const moduleAndData = concat([recoveryModuleAddress, initData]);

  const addModuleTx =
    await account.addModule.populateTransaction(moduleAndData);

  const tx = await prepareTeeTx(
    provider,
    account,
    addModuleTx,
    await teeValidator.getAddress(),
    keyPair
  );

  let accountNonce = await getContractNonce(account, provider);
  const txReceipt = await provider.broadcastTransaction(
    utils.serializeEip712(tx)
  );
  await txReceipt.wait();
  await waitTillNonceUpdateContract(account, accountNonce, provider);

  expect(await account.isModule(recoveryModuleAddress)).to.be.true;

  const expectedModules = [recoveryModuleAddress];

  expect(await account.listModules()).to.deep.eq(expectedModules);

  const newKeyPair = genKey();
  const newPublicKey = encodePublicKey(newKeyPair);

  console.log("accountAddress:        ", accountAddress);
  console.log("");
  console.log("newPublicKey:          ", newPublicKey);
  console.log("");
  console.log("recoveryModuleAddress: ", recoveryModuleAddress);
  console.log("");
  console.log(
    `update plugin ${recoveryModuleAddress} to new owner ${newPublicKey} for account ${accountAddress}`
  );
};

async function getNonce(wallet: Wallet): Promise<number> {
  return await wallet.getNonce();
}

async function getContractNonce(
  account: Contract | unknown,
  provider: Provider
): Promise<number> {
  return await provider.getTransactionCount(
    await (account as Contract).getAddress()
  );
}

async function waitTillNonceUpdate(
  wallet: Wallet,
  nonce: number
): Promise<void> {
  while ((await wallet.getNonce()) === nonce) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function waitTillNonceUpdateContract(
  account: Contract | unknown,
  nonce: number,
  provider: Provider
): Promise<void> {
  while (
    (await provider.getTransactionCount(
      await (account as Contract).getAddress()
    )) === nonce
  ) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

main().catch((error) => {
  console.log(error);
  process.exit(0);
});
