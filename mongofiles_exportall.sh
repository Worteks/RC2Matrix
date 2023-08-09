#!/bin/bash

dbname=$1
user=$2
pass=$3
output=$(mktemp -d)

cd ${output}

for i in $(mongofiles -u ${user} -p ${pass} --db=${dbname} --prefix=rocketchat_uploads list); do
  echo $i
  mongofiles -u ${user} -p ${pass} --db=${dbname} --prefix=rocketchat_uploads get ${i}
done

echo "Exported to ${output}"
