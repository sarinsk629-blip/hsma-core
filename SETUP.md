# 🚀 HSMA Testnet Setup Guide

## Quick Start (Docker)

```bash
# One command — a full testnet with 2 nodes
docker-compose up -d

# Check the nodes
curl http://localhost:32233/api
curl http://localhost:32234/api

# Send encrypted envelopes
docker exec hsma-faucet ./build/envfaucet node1 31233

# View the logs
docker logs hsma-node1
docker logs hsma-node2
```

## Manual Build (From Source)

### Prerequisites
- Linux (Ubuntu 22.04+ or Debian 12+) or macOS
- C++20 compiler (clang++ or g++)
- CMake 3.16+
- Ninja build system
- Python 3.10+

### Steps

```bash
# 1. Clone
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core

# 2. Run the verification gate
./scripts/gate.sh
# → 41 goldens generated, 34/34 tests, GATE GREEN

# 3. Start node 1
./build/epoch_node 31233

# 4. In another terminal, start node 2 (connected to node 1)
./build/epoch_node 31234 --seed 127.0.0.1:31233

# 5. Send encrypted envelopes
./build/envfaucet 127.0.0.1 31233

# 6. Send decree faucet
python3 tools/faucet.py 127.0.0.1 31233 10

# 7. Cast votes
./build/votecast 127.0.0.1 31233

# 8. Check the explorer
curl http://localhost:32233/api
# Or open http://localhost:32233 in a browser
```

## AWS Deployment

```bash
# Launch an EC2 instance (t2.medium, Ubuntu 22.04)
# SSH in and run:

sudo apt-get update
sudo apt-get install -y cmake ninja-build clang python3 git build-essential
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
./scripts/gate.sh

# Start the node (survives SSH disconnect)
nohup ./build/epoch_node 31233 > node.log 2>&1 &

# Verify it's running
curl http://localhost:32233/api
```

## Connecting to the Testnet

```bash
# From any machine, connect your node to the AWS seed:
./build/epoch_node 31234 --seed <AWS_IP>:31233

# Your node will:
# - Exchange BLS-signed MSSC votes
# - Receive encrypted mempool envelopes
# - Participate in the convergence
# - Produce π_E epoch proofs
# - Derive PoUW consensus weight
```
