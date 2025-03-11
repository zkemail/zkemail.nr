# Development Guide

This document provides instructions for setting up the development environment and contributing to the project.

## Prerequisites

Before you begin, ensure you have the correct versions of the required tools installed:

- **Barretenberg (bb)**: version 0.66.0
- **Nargo**: version 1.0.0-beta.1
- **Node.js**: Latest LTS version recommended
- **yarn**: Latest stable version

### Installing Required Tools

#### 1. Installing Noir

Noir can be installed using `noirup`, a installation script:

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
```

Then install the specific version needed for this project:
```bash
noirup -v 1.0.0-beta.1
```

#### 2. Installing Barretenberg (BB)

Barretenberg is the proving backend we use. Install it using `bbup`:

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
```

Then install the specific version needed for this project:
```bash
bbup -v 0.66.0
```

#### 3. Installing Node.js and yarn

1. Install nvm (Node Version Manager):
   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
   ```

2. Restart your terminal or run:
   ```bash
   export NVM_DIR="$HOME/.nvm"
   [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
   ```

3. Install and use the LTS version of Node.js:
   ```bash
   nvm install --lts
   nvm use --lts
   ```

4. Install yarn:
   ```bash
   npm install -g yarn
   ```

### Verifying Installations

You can verify your installations by running:

```bash
bb --version    # Should output: 0.66.0
nargo --version # Should output: nargo version = 1.0.0-beta.1
node --version  # Should show your Node.js version
yarn --version  # Should show your yarn version
```

## Development Workflow

### Installing Dependencies

After cloning the repository, install the project dependencies:

```bash
yarn install
```

### Testing

Before making any changes, run the test suite to ensure everything works:

```bash
yarn test
```

### Compiling Circuits

1. Use the provided `compile.sh` script:
   ```bash
   ./compile.sh
   ```

### Working with Proofs

After compiling your circuits, you can:

1. Generate a proof:
   ```bash
   bb prove -b ./target/circuit_name.json -w ./target/circuit_name.gz -o ./target/proof
   ```

2. Generate verification key:
   ```bash
   bb write_vk -b ./target/circuit_name.json -o ./target/vk
   ```

3. Verify the proof:
   ```bash
   bb verify -k ./target/vk -p ./target/proof
   ```

Note: Replace `circuit_name` with your actual circuit name.

## Contributing

1. Make sure you have the correct versions of tools installed as specified above
2. Fork the repository and create a new branch for your feature or fix
3. Install dependencies with `yarn install`
4. Make your changes
5. Run the test suite with `yarn test` to ensure nothing is broken
6. Compile the circuits using `compile.sh` to ensure everything works
7. Test your changes by generating and verifying proofs
8. Submit a Pull Request with a clear description of your changes

## Troubleshooting

If you encounter any issues:
1. Verify you have the correct versions of bb and nargo installed
2. Make sure the `compile.sh` script has execution permissions (`chmod +x compile.sh`)
3. Check that all dependencies are properly installed
4. If you're having issues with proofs:
   - Ensure you're using the most recent versions of compiled circuits
   - Try deleting the `target` folder and recompiling fresh
   - Verify the paths to your circuit files are correct

## Need Help?

If you need assistance or have questions, please:
1. Check existing issues in the repository
2. Check the [official Noir documentation](https://noir-lang.org/docs/getting_started/quick_start)
3. Create a new issue if your problem hasn't been addressed
