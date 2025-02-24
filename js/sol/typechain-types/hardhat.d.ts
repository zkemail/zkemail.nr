/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { ethers } from "ethers";
import {
  DeployContractOptions,
  FactoryOptions,
  HardhatEthersHelpers as HardhatEthersHelpersBase,
} from "@nomicfoundation/hardhat-ethers/types";

import * as Contracts from ".";

declare module "hardhat/types/runtime" {
  interface HardhatEthersHelpers extends HardhatEthersHelpersBase {
    getContractFactory(
      name: "VerifierTest",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.VerifierTest__factory>;
    getContractFactory(
      name: "HonkVerifier",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.HonkVerifier__factory>;
    getContractFactory(
      name: "IVerifier",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IVerifier__factory>;

    getContractAt(
      name: "VerifierTest",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.VerifierTest>;
    getContractAt(
      name: "HonkVerifier",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.HonkVerifier>;
    getContractAt(
      name: "IVerifier",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IVerifier>;

    deployContract(
      name: "VerifierTest",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.VerifierTest>;
    deployContract(
      name: "HonkVerifier",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.HonkVerifier>;
    deployContract(
      name: "IVerifier",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IVerifier>;

    deployContract(
      name: "VerifierTest",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.VerifierTest>;
    deployContract(
      name: "HonkVerifier",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.HonkVerifier>;
    deployContract(
      name: "IVerifier",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IVerifier>;

    // default types
    getContractFactory(
      name: string,
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<ethers.ContractFactory>;
    getContractFactory(
      abi: any[],
      bytecode: ethers.BytesLike,
      signer?: ethers.Signer
    ): Promise<ethers.ContractFactory>;
    getContractAt(
      nameOrAbi: string | any[],
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
  }
}
