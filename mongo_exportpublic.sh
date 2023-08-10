#!/bin/bash

# This script exports users, rooms, messages and uploaded files from RocketChat. Only public rooms and their messages are exported.
# Export will be in /tmp/tmp.xxxxxx, which is printed at the end of the script

dbname=$1
user=$2
pass=$3
output=$(mktemp -d)
#output="/tmp/montmp"

cd ${output}

echo "Exporting users and public rooms"
# rocketchat_users.json will contain all users, rocketchat_room_tmp.json will contains all rooms
/opt/rh/rh-mongodb32/root/usr/bin/mongoexport --collection=users --db=${dbname} --out=rocketchat_users.json -u ${user} -p ${pass}
/opt/rh/rh-mongodb32/root/usr/bin/mongoexport --collection=rocketchat_room --db=${dbname} --out=rocketchat_room_tmp.json -u ${user} -p ${pass}

# filter rooms to export, here only public chats. rocketchat_room.json will contain only public rooms
grep -e "\"t\":\"c\"" rocketchat_room_tmp.json > rocketchat_room.json
rm rocketchat_room_tmp.json

# ${publicrooms} is the list of public room ids, such as "kjkjknbnbb","hjhjhjHgd45"
publicrooms=$(cat rocketchat_room.json | sed -E "s/^\{\"_id\":(\"[^\"]+\").*$/\1/g" | sed -ze "s/\n/,/g" | sed "s/,$//g")

echo "Public rooms are: ${publicrooms}"

echo "Exporting public messages"
# rocketchat_message.json will contain messages only from ${publicrooms}
/opt/rh/rh-mongodb32/root/usr/bin/mongoexport --collection=rocketchat_message --db=${dbname} --out=rocketchat_message.json -u ${user} -p ${pass} --query="{\"rid\": {\"\$in\" : [${publicrooms}]} }"

echo "Exporting public attachments"
# Finally, extract all files linked by public messages
mkdir -p files
cd files
while IFS="" read -r p || [ -n "$p" ]
do
  link=$(printf '%s\n' "$p" | grep "title_link" | sed -E "s/.*\"title_link\":(\"[^\"]+\").*$/\1/g" | sed -E "s%^\"/file-upload/([^/]+)/.*$%\1%g")
  if [ -n "${link##+([[:space:]])}" ]; then
    echo ${link}
    mongofiles -u ${user} -p ${pass} --db=${dbname} --prefix=rocketchat_uploads get ${link}
  fi
done < ../rocketchat_message.json

# To export all files, uncomment the following part
# for i in $(mongofiles -u ${user} -p ${pass} --db=${dbname} --prefix=rocketchat_uploads list); do
#   echo $i
#   mongofiles -u ${user} -p ${pass} --db=${dbname} --prefix=rocketchat_uploads get ${i}
# done

# Print output directory
echo "Exported to ${output}"
