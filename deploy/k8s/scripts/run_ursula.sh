#! /bin/bash

# set -e

# 1st wait for the geth container to start up and create an account
while [ ! -s "/mnt/data/address.txt" ]
do
  echo "waiting for geth account creation"
  sleep 1
done

# get the address of the account created by geth
export ACCOUNT_ADDRESS=`cat /mnt/data/address.txt`;

while [ ! -e "/mnt/data/geth/geth.ipc" ]
do
  echo "waiting for geth startup"
  sleep 1
done
sleep 2

# and our ip address
export MY_IP=$(wget -q -O - ifconfig.me);

nucypher --debug ursula init --provider-uri=$NUCYPHER_PROVIDER_URI --network $NUCYPHER_NETWORK --rest-host $NUCYPHER_REST_HOST --checksum-address $ACCOUNT_ADDRESS

# tar the newly created config
tar -C $NUCYPHER_CONFIG_ROOT -zcvf /mnt/data/$ACCOUNT_ADDRESS@$MY_IP.tar.gz $NUCYPHER_CONFIG_ROOT

# and send it to S3
python /code/deploy/k8s/scripts/publish_config.py

nucypher --debug ursula run --checksum-address $ACCOUNT_ADDRESS
sleep 10000  # so you can shell in after everything doesn't work
