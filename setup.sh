#!/bin/bash
set -x

# Network
if [[ $(docker network ls |grep vembu-network |wc -l ) -lt 1 ]]; then
	docker network create --subnet=172.18.0.0/16 vembu-network
fi

# Start Database container
mkdir DB
while [[ $(docker ps -a |grep VembuDatabase|wc -l) -ge 1 ]]; do
	docker kill VembuDatabase
	docker rm VembuDatabase
	sleep 1
done
docker run --name VembuDatabase --network vembu-network --ip 172.18.0.2 -p 5432:5432 -d -e POSTGRES_PASSWORD=admin -e POSTGRES_USER=postgres -e POSTGRES_DB=SGDatabase -v  $PWD/DB:/vembu vembubdr/bdr-latest:psql-latest

# Wait for database port to open
echo -c "Waiting for database to become available..."
while ! timeout 1 bash -c "echo > /dev/tcp/localhost/5432" ; do 
	echo -c "."
	sleep 1; 
done
echo

# Start APP container
mkdir APP
while [[ $(docker ps -a |grep VembuBDR4201|wc -l) -ge 1 ]]; do
	docker kill VembuBDR4201
	docker rm VembuBDR4201
	sleep 1
done

docker run --name VembuBDR4201 --network vembu-network --ip 172.18.0.3 --add-host VembuDatabase:172.18.0.2 --privileged=true -i -t -d --device /dev/fuse --privileged -p 6060:6060 -p 32004:32004 -v $PWD/APP:/vembu vembubdr/bdr-latest:vembubdr-4201-u1

# Wait for app port to open
echo -c "Waiting for application to become available..."
while ! timeout 1 bash -c "echo > /dev/tcp/localhost/6060" ; do 
	echo -c "."
	sleep 1; 
done
echo
