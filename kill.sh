#!/bin/bash
#set -x

# containers
echo -n "Killing containers "
for id in $(docker ps|grep vembu|awk '{ print $1 }' ); do
	docker kill $id
	echo -n " . "
done
echo "done."


# Network
echo -n "Removing network "
if [[ $(docker network ls |grep vembu-network |wc -l ) -ge 1 ]]; then
	echo -n " . "
	docker network rm vembu-network
	echo -n " . "
fi
echo "done."

echo "Vembu configuraiton removed"