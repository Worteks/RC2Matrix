# RC2Matrix

Rocketchat to Matrix/Synapse migration script. Workflow is largely inspired by [https://git.verdigado.com/NB-Public/rocketchat2matrix](https://git.verdigado.com/NB-Public/rocketchat2matrix).

*** WARNING : THIS IS WIP, USE AT YOUR OWN RISKS ***

## Exporting RocketChat data

Currently manually via mongodb. Run the following on the server:

```shell
mongoexport --collection=rocketchat_message --db=<dbname> --out=rocketchat_messages.json -u <dbuser> -p <dbpass>  --sort='{ts: 1}'
mongoexport --collection=rocketchat_room --db=<dbname> --out=rocketchat_rooms.json -u <dbuser> -p <dbpass>
mongoexport --collection=users --db=<dbname> --out=rocketchat_users.json -u <dbuser> -p <dbpass>
```

Optionnaly, you can run `./mongofiles_exportall.sh <dbname> <dbuser> <dbpass>` to export files and images (in this repository). It will export files in a temporary directory, printed at the end of the script.

Instead, you can also run `./mongo_exportpublic.sh <dbname> <dbuser> <dbpass>` to export only public data (all users, public rooms, messages in these public rooms only, attachments mentionned in these messages only).

## Preparing Synapse server

On the Synapse server you need an admin account (user/pass) or directly its token.

You also need an application service. To register an application service, add in `homeserver.yaml` :
```YAML
app_service_config_files:
- /your_path/rc2matrix.yaml

rc_joins:
  local:
    per_second: 1024
    burst_count: 2048
rc_joins_per_room:
  per_second: 1024
  burst_count: 2048
rc_message:
  per_second: 1024
  burst_count: 2048
rc_invites:
  per_room:
    per_second: 1024
    burst_count: 2048
  per_user:
    per_second: 1024
    burst_count: 2048
  per_issuer:
    per_second: 1024
    burst_count: 2048
```

And to create a `rc2matrix.yaml` (you need to customize the two tokens) :
```YAML
url: null
as_token: ASecretASToken
hs_token: ASecretHSToken
id: rc2matrix
sender_localpart: rc2matrix
namespaces:
  users:  # List of users we're interested in
    - exclusive: false
      regex: ".*"
  aliases:
    - exclusive: false
      regex: ".*"
  rooms:
    - exclusive: false
      regex: ".*"

```

## Running RC2Matrix

If you do not have your admin token, you can obtain it with `./rc2matrix.py -v -n <your matrix hostname> -u <user_admin> -p <pass_admin>`. Token will be printed on the console.

Then, to import rooms, users and messages into Synapse : `./rc2matrix.py -v -n <your matrix hostname> -t <admin_token> -a <ASecretASToken> -i <your folder containing the exports>` (the ASecretASToken is defined in `rc2matrix.yaml`).

In your folder containing the exports, you should have `rocketchat_messages.json`, `rocketchat_rooms.json` and `rocketchat_users.json` files, as well as a folder `files/` containing the exported files.

You can remove `-v` for less verbose output.

## How does it work ?

First, the data exported from RC is three JSON files containing rooms, users, and messages. Contents are described on the RC website ([rooms](https://developer.rocket.chat/reference/api/schema-definition/room), [messages](https://developer.rocket.chat/reference/api/schema-definition/message)). Files are not really JSON, but each line is a valid JSON, which can thus be processed sequentially.

On the Synapse side, we use both the [Matrix client-server API](https://spec.matrix.org/latest/client-server-api/), with the admin and application service account, and the [Synapse Admin API](https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/), with the admin account. Some operations (such as creating rooms) are only authorized to the admin user, whereas some others (such as altering the timestamps of the messages or masquerading identities) are only authorized to the application service, hence these two needed tokens.

First the rooms are created (or retrieved if already existing). Then, users are added, without authentication method : they will have to authenticate through an external system. Finally, messages are posted on behalf of these users. Rooms settings (public, private, DM) should be quite similar to RC settings but there may be some unexpected cases. DM messages appear in dedicated rooms.

This script currently only import messages, in order to provide a usable migration path. Images, threads, emojis and advanced formatting is only partially handled.

While the RC data will not be altered (there is just an export), Synapse data will obviously be altered. You should not run this script against an already used server, as it may have unexpected issues. You should run this script against a fresh Synapse server and carefully check the result.
