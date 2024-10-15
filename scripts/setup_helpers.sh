#!/bin/bash

git clone https://github.com/zkemail/zk-email-verify
cd zk-email-verify
git checkout 6e08c674fe9a02bc3a1d59e93992b0afabd7fe56
cd packages/helpers
yarn && yarn tsc