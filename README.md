# Dirichlet Reputation Network on Hyperledger Fabric

This repository instantiates the Dirichlet-based reputation model described in your paper on top of a two-organization Hyperledger Fabric 2.5 network (Org1 = issuer, Org2 = verifier). It contains:

- `chaincode/reputation`: Go chaincode implementing the four-state Dirichlet vector, tri-phase decay, hybrid scoring, and adaptive on-chain sampling hints.
- `network`: Fabric network artifacts (crypto/configtx specs, docker-compose, gateway connection profiles, and generation scripts).
- `applications/python`: Python client that uses the new Fabric Gateway SDK to emulate different IoT device personas and stream evidence into the ledger.

## Prerequisites

- Docker & Docker Compose
- Go 1.20+
- Hyperledger Fabric binaries (`cryptogen`, `configtxgen`, `peer`, Fabric CA client) v2.5
- Python 3.10+ and `virtualenv`

Clone or copy this folder to `~/test` as required.

## 1. Generate crypto material & channel artifacts

```bash
cd ~/test/network
chmod +x scripts/generate.sh
./scripts/generate.sh
```

The script produces `crypto-config/` and `channel-artifacts/` using the provided `crypto-config.yaml` and `configtx.yaml`. Adjust MSP names or subject details if your environment requires different CNs.

## 2. Launch the Fabric network

```bash
cd ~/test/network
docker compose up -d
```

Containers launched:

- `ca_org1`, `ca_org2`
- `orderer.example.com`
- `peer0.org1.example.com`, `peer0.org2.example.com`
- `cli` toolbox

## 3. Create the channel and set anchor peers

Use the `cli` container (or host `peer` binary) to submit channel transactions:

```bash
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_MSPCONFIGPATH=$PWD/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
export ORDERER_CA=$PWD/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

peer channel create -o localhost:7050 -c reputationchannel -f ./channel-artifacts/reputation.tx --outputBlock ./channel-artifacts/reputationchannel.block --tls --cafile $ORDERER_CA
peer channel join -b ./channel-artifacts/reputationchannel.block
peer channel update -o localhost:7050 -c reputationchannel -f ./channel-artifacts/Org1MSPanchors.tx --tls --cafile $ORDERER_CA

# switch environment to Org2
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_MSPCONFIGPATH=$PWD/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer channel join -b ./channel-artifacts/reputationchannel.block
peer channel update -o localhost:7050 -c reputationchannel -f ./channel-artifacts/Org2MSPanchors.tx --tls --cafile $ORDERER_CA
```

## 4. Package, install, approve, and commit the chaincode

```bash
cd ~/test
peer lifecycle chaincode package reputation.tgz --path chaincode/reputation --lang golang --label reputation_1

# Org1 install & approve
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_MSPCONFIGPATH=$PWD/network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
peer lifecycle chaincode install reputation.tgz
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled | grep reputation_1 | awk -F "[, ]+" '{print $3}')
peer lifecycle chaincode approveformyorg --channelID reputationchannel --name reputation --version 1.0 --package-id $PACKAGE_ID --sequence 1 --tls --cafile $ORDERER_CA

# Org2 install & approve
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_MSPCONFIGPATH=$PWD/network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051
peer lifecycle chaincode install reputation.tgz
peer lifecycle chaincode approveformyorg --channelID reputationchannel --name reputation --version 1.0 --package-id $PACKAGE_ID --sequence 1 --tls --cafile $ORDERER_CA

# Commit definition
peer lifecycle chaincode commit -o localhost:7050 --channelID reputationchannel --name reputation --version 1.0 --sequence 1 --tls --cafile $ORDERER_CA \
  --peerAddresses localhost:7051 --tlsRootCertFiles network/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt \
  --peerAddresses localhost:9051 --tlsRootCertFiles network/crypto-config/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
```

## 5. Simulate device interactions via Fabric Gateway (Python)

1. Update `applications/python/config.yaml` if your crypto paths or endpoints differ.
2. Install dependencies and run the simulator:

```bash
cd ~/test/applications/python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python simulate_devices.py
```

The script:

- Registers four representative device personas.
- Streams stochastic evidence using the hybrid scoring function.
- Prints the evolving score, Dirichlet probabilities, adaptive profile, and sampling policy per device.

Modify `DeviceScenario` definitions or loop counts to evaluate resilience against benign flapping, suspicious probing, and malicious bursts. The printed `score`, `profile`, and `urgentFlag` let you validate that:

- Trusted nodes decay slowly (stage-1 linear) and retain high access scores.
- Suspicious and malicious nodes quickly drop below thresholds due to the exponential penalty on `P_Malicious`.
- Long-idle devices re-enter with small denominators, so even small malicious weights cause large probability swings (stage-3 power-law behavior).

## 6. Next steps

- Connect Org2 clients using `network/gateways/org2_connection.json` to verify cross-organization endorsements.
- Feed real telemetry or replay traces by modifying the simulator to pull from message queues or CSV logs.
- Expose the adaptive sampling hints (`profile`, `sampleRate`, `urgentFlag`) to your blockchain/application layer for differential storage policies.
