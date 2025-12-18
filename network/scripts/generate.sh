#!/usr/bin/env bash
set -euo pipefail

# Generates crypto materials and channel artifacts for the reputation network.
# Requires cryptogen and configtxgen binaries in PATH.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRYPTO_DIR="${ROOT_DIR}/crypto-config"
ARTIFACTS_DIR="${ROOT_DIR}/channel-artifacts"

rm -rf "${CRYPTO_DIR}" "${ARTIFACTS_DIR}"
mkdir -p "${CRYPTO_DIR}" "${ARTIFACTS_DIR}"

cryptogen generate --config="${ROOT_DIR}/crypto-config.yaml" --output="${CRYPTO_DIR}"

export FABRIC_CFG_PATH="${ROOT_DIR}"

configtxgen -profile ReputationOrdererGenesis -channelID system-channel -outputBlock "${ARTIFACTS_DIR}/genesis.block"
configtxgen -profile ReputationChannel -outputCreateChannelTx "${ARTIFACTS_DIR}/reputation.tx" -channelID reputationchannel
configtxgen -profile ReputationChannel -outputAnchorPeersUpdate "${ARTIFACTS_DIR}/Org1MSPanchors.tx" -channelID reputationchannel -asOrg Org1MSP
configtxgen -profile ReputationChannel -outputAnchorPeersUpdate "${ARTIFACTS_DIR}/Org2MSPanchors.tx" -channelID reputationchannel -asOrg Org2MSP
