#!/usr/bin/env bash
# HSMA AWS deployment: one command to launch a testnet node
# Prerequisites: AWS CLI configured, EC2 key pair exists

set -euo pipefail

echo "═══════════════════════════════════════════"
echo "  HSMA AWS Testnet Node Deployment"
echo "═══════════════════════════════════════════"

# Configuration
INSTANCE_TYPE="t2.medium"
AMI="ami-0c02fb55956c7d316"  # Ubuntu 22.04 LTS us-east-1
KEY_NAME="${1:-hsma-key}"
SECURITY_GROUP="hsma-testnet"

# Create the security group if it doesn't exist
aws ec2 describe-security-groups --group-names $SECURITY_GROUP 2>/dev/null || {
    echo "[aws] creating security group..."
    aws ec2 create-security-group --group-name $SECURITY_GROUP \
        --description "HSMA testnet node"
    aws ec2 authorize-security-group-ingress --group-name $SECURITY_GROUP \
        --protocol tcp --port 22 --cidr 0.0.0.0/0
    aws ec2 authorize-security-group-ingress --group-name $SECURITY_GROUP \
        --protocol tcp --port 31233 --cidr 0.0.0.0/0
    aws ec2 authorize-security-group-ingress --group-name $SECURITY_GROUP \
        --protocol tcp --port 31234 --cidr 0.0.0.0/0
    aws ec2 authorize-security-group-ingress --group-name $SECURITY_GROUP \
        --protocol tcp --port 32233 --cidr 0.0.0.0/0
    aws ec2 authorize-security-group-ingress --group-name $SECURITY_GROUP \
        --protocol tcp --port 32234 --cidr 0.0.0.0/0
}

# Launch the instance
echo "[aws] launching $INSTANCE_TYPE instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id $AMI \
    --instance-type $INSTANCE_TYPE \
    --key-name $KEY_NAME \
    --security-group-ids $SECURITY_GROUP \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=hsma-testnet}]' \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "[aws] instance: $INSTANCE_ID"
echo "[aws] waiting for it to start..."
aws ec2 wait instance-running --instance-ids $INSTANCE_ID

# Get the public IP
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

echo "[aws] public IP: $PUBLIC_IP"
echo "[aws] waiting for SSH to be available..."
sleep 30

# Deploy HSMA on the instance
echo "[aws] deploying HSMA..."
ssh -o StrictHostKeyChecking=no ubuntu@$PUBLIC_IP <<'DEPLOY'
sudo apt-get update && sudo apt-get install -y cmake ninja-build clang python3 git build-essential
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
./scripts/gate.sh
echo "═══════════════════════════════"
echo "  HSMA Gate: GATE GREEN"
echo "  Starting the testnet node..."
echo "═══════════════════════════════"
nohup ./build/epoch_node 31233 > node.log 2>&1 &
sleep 5
curl -s http://localhost:32233/api
echo ""
echo "HSMA testnet node is LIVE"
DEPLOY

echo ""
echo "═══════════════════════════════════════════"
echo "  DEPLOYMENT COMPLETE"
echo "═══════════════════════════════════════════"
echo "  Node IP: $PUBLIC_IP"
echo "  P2P Port: $PUBLIC_IP:31233"
echo "  Explorer: http://$PUBLIC_IP:32233"
echo "  SSH: ssh ubuntu@$PUBLIC_IP"
echo "═══════════════════════════════════════════"
