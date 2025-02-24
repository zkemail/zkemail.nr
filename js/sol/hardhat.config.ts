import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true
    }
  }
};

export default config;
