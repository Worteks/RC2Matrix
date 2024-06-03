#!/usr/bin/python3

import argparse
import sys
import os
import pprint as ppprint
import json
import requests
from datetime import datetime
import re
import markdown
import errno
# for retries
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import magic

import emoji # for reactions

## TODO
# Handle topic/announcement/announcementDetails/md of original room

# globals
roomsfile = "rocketchat_rooms.json"
usersfile = "rocketchat_users.json"
histfile = "rocketchat_messages.json"
verbose = False
messages_cachefile = "messages_cache.txt"
users_cachefile = "users_cache.txt"
rooms_cachefile = "rooms_cache.txt"


# pretty printing functions, switched by verbose argument
def terminal_size():
    import fcntl
    import termios
    import struct
    h, w, hp, wp = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))
    return w, h

def pprint(name, data):
    if verbose:
        w, h = terminal_size()
        pp = ppprint.PrettyPrinter(indent=2, width=w)
        print(name + ": ")
        pp.pprint(data)
        print("\n\n")

def vprint(data):
    if verbose:
        print(str(data))
        print("\n\n")

# Arguments parser
def createArgParser():
    parser = argparse.ArgumentParser(description='Launches RC2Matrix migration')
    parser.add_argument("-i", type=str, help='inputs folder, defaults to inputs/', dest="inputs", default="inputs/")
    parser.add_argument("-n", type=str, help='Matrix server', dest="hostname", default="localhost")
    parser.add_argument("-u", type=str, help='Admin username', dest="username", default="admin")
    parser.add_argument("-p", type=str, help='Admin password', dest="password", default="password")
    parser.add_argument("-t", type=str, help='Admin token', dest="token", default=None )
    parser.add_argument("-a", type=str, help='Application token', dest="apptoken", default=None )
    parser.add_argument("-s", type=str, help='Starting timestamp (excluded)', dest="startts", default=0 )
    parser.add_argument("-k", help='Disable TLS certificate check', dest="nocertcheck", action="store_true")
    parser.add_argument("-v", help='verbose', dest="verbose", action="store_true")

    return parser

# Try to format a markdown message into html
def format_message(raw):
    #formatted = raw
    #formatted = re.sub("```(.+)```", "<code>\\1</code>", formatted)
    #formatted = re.sub("`(.+)`", "<code>\\1</code>", formatted)
    formatted = markdown.markdown(raw)
    if len(formatted) <= len(raw)+7: # markdown adds <p></p> tags
        api_params = {'msgtype': 'm.text', 'body': raw}
    else:
        api_params = {'msgtype': 'm.text', 'body': raw,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted}

    return api_params

# Add a related event, currently unused
def relate_message(raw, ancestor):
    api_params = {'msgtype': 'm.text', 'body': raw,
        "m.relates_to": {
            "m.in_reply_to": {
                "event_id": ancestor
                }
            }
        }

    return api_params

def invite(api_base, api_headers_admin, tgtroom, tgtuser):

    # Method 1, use admin user (possible for public rooms)
    api_endpoint = api_base + "_synapse/admin/v1/join/" + tgtroom
    api_params = {'user_id': tgtuser}
    response = requests.post(api_endpoint, json=api_params, headers=api_headers_admin)
    vprint(response.json())

    if response.status_code != 200:
        # Method 2, use creator for private rooms : get creator's token, use it to invite, join with tgtuser, logout both

        # Get creator and its token
        ## Get creator
        api_endpoint = api_base + "/_synapse/admin/v1/rooms/" + tgtroom
        response = requests.get(api_endpoint, headers=api_headers_admin)
        vprint(response.json())
        creator=response.json()["creator"]

        ## Get its token
        api_endpoint = api_base + "_synapse/admin/v1/users/" + creator + "/login"
        response = session.post(api_endpoint, headers=api_headers_admin)
        vprint(response.json())
        creator_token = response.json()['access_token']
        api_headers_creator =  {"Authorization":"Bearer " + creator_token}
        vprint(api_headers_creator)

        # invite tgtuser with creator's token
        api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + "/invite"
        api_params = {'user_id': tgtuser}
        response = requests.post(api_endpoint, json=api_params, headers=api_headers_creator)
        vprint(response.json())

        # Logout creator
        api_endpoint_logout = api_base + "/_matrix/client/v3/logout"
        response_logout = requests.post(api_endpoint_logout, headers=api_headers_creator)

        # join with tgtuser
        api_endpoint = api_base + "_synapse/admin/v1/users/" + tgtuser + "/login"
        response = session.post(api_endpoint, headers=api_headers_admin)
        vprint(response.json())
        tgtuser_token = response.json()['access_token']
        api_headers_tgtuser =  {"Authorization":"Bearer " + tgtuser_token}
        vprint(api_headers_tgtuser)
        api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + "/join"
        response = requests.post(api_endpoint, headers=api_headers_tgtuser)
        vprint(response.json())

        # logout tgtuser
        api_endpoint_logout = api_base + "/_matrix/client/v3/logout"
        response_logout = requests.post(api_endpoint_logout, headers=api_headers_tgtuser)

        # Check join
        if response.status_code != 200:
            print("error inviting " + tgtuser + " to " + tgtroom)
            print(response.json())
            exit(1)


if __name__ == '__main__':
    parser = createArgParser()
    args = parser.parse_args()
    verbose = args.verbose
    mime = magic.Magic(mime=True)

    if (verbose):
        print("Arguments are: ", args)

    if (args.nocertcheck):
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context
        ssl.SSLContext.verify_mode = property(lambda self: ssl.CERT_NONE, lambda self, newval: None)
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    api_base = "https://" + args.hostname + "/"

    # Obtain an admin token if not provided
    if args.token is None:
        api_endpoint = api_base + "_matrix/client/v3/login"
        api_params = {"type": "m.login.password","user": args.username,"password": args.password,"device_id": "rc2m"}
        response = requests.post(api_endpoint, json=api_params)
        vprint(response.json())
        if response.status_code == 200:
            token=response.json()["access_token"]
            vprint("Token is " + token)
            exit(0)
        else:
            exit("failed to connect")

    # admin allows to connect as the admin user, as allows to connect as the application service
    api_headers_admin =  {"Authorization":"Bearer " + args.token}
    api_headers_as =  {"Authorization":"Bearer " + args.apptoken}

    # retry in case of error
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Import users
    print("Importing users...")
    users = set()
    # load cache
    nbcache = 0
    try:
        with open(users_cachefile, encoding='utf8') as f:
            for line in f:
                nbcache+=1
                users.add(line.rstrip('\n'))
        f.close()
        print("Restored " + str(nbcache) + " user ids from cache")
    except FileNotFoundError:
        print("No user cache to restore")
    cache = open(users_cachefile, 'a')
    # import new users
    with open(args.inputs + usersfile, 'r') as jsonfile:
        # Each line is a JSON representing a RC user
        for line in jsonfile:
            currentuser = json.loads(line)
            pprint("current user", currentuser)
            if ("username" not in currentuser):
                continue
            username=currentuser['username'].lower()
            if "name" in currentuser and isinstance(currentuser['name'], str):
                displayname=currentuser['name']
            else:
                displayname=username
            if username in users:
                print("user " + username + " already processed (in cache), skipping")
                continue
            # matrix username will be @username:server
            api_endpoint = api_base + "_synapse/admin/v2/users/@" + username + ":" + args.hostname
            api_params = {"admin": False, "displayname": displayname}
            response = session.put(api_endpoint, json=api_params, headers=api_headers_admin)
            if response.status_code < 200 or response.status_code > 299: #2xx
                print("error adding user")
                print(currentuser)
                print(response.json())
                print(response.status_code)
                exit(1)

            # avatar
            if "avatarETag" in currentuser:
                try: # try to find the file in the export
                    api_endpoint = api_base + "_matrix/media/v3/upload?user_id=@" + username + ":" + args.hostname
                    api_params = {'filename': username}
                    api_headers_file = api_headers_as.copy()
                    # api_headers_file['Content-Type'] = attachment['image_type']
                    localfile=currentuser["avatarETag"]
                    with open(args.inputs + "avatars_users/" + localfile, 'rb') as f:
                        # upload as a media to matrix
                        api_headers_file['Content-Type'] = mime.from_file(args.inputs + "avatars_users/" + localfile)
                        response = session.post(api_endpoint, json=api_params, headers=api_headers_file, data=f)
                    vprint(response.json())
                    if response.status_code != 200: # Upload problem
                        vprint(response)
                        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), localfile)
                    mxcurl=response.json()['content_uri'] # URI of the uploaded media
                    # Then post a user update referencing this media
                    api_endpoint = api_base + "_synapse/admin/v2/users/@" + username + ":" + args.hostname
                    api_params = {"admin": False, "avatar_url": mxcurl}
                    response = session.put(api_endpoint, json=api_params, headers=api_headers_admin)
                    if response.status_code < 200 or response.status_code > 299: #2xx
                        print("error adding avatar for user")
                        print(currentuser)
                        print(response.json())
                        print(response.status_code)
                        exit(1)

                except FileNotFoundError: # We do not have the linked attachment
                    print("Avatar not found for " + username + ", in " + localfile)

            cache.write(username + "\n")
            vprint(response.json())
    cache.close()

    # Import rooms
    print("Importing rooms...")
    roomids = {}  # Map RC_roomID to Matrix_roomID
    # load cache
    nbcache = 0
    try:
        with open(rooms_cachefile, encoding='utf8') as f:
            for line in f:
                nbcache+=1
                atoms = line.rstrip('\n').split('$')
                roomids[atoms[0]] = atoms[1]
        f.close()
        print("Restored " + str(nbcache) + " room ids from cache")
    except FileNotFoundError:
        print("No room cache to restore")
    cache = open(rooms_cachefile, 'a')
    # Import new rooms
    with open(args.inputs + roomsfile, 'r') as jsonfile:
        # Each line is a JSON representing a RC room
        for line in jsonfile:
            currentroom = json.loads(line)
            if currentroom['_id'] in roomids:
                print("room " + currentroom['name'] + " already processed (in cache), skipping")
                continue
            pprint("current room", currentroom)

            api_headers_create = api_headers_admin
            createroom_usertoken = False
            if 'u' in currentroom:
                try:
                    owner_id = "@" + currentroom['u']['username'] + ":" + args.hostname
                    api_endpoint = api_base + "_synapse/admin/v2/users/" + owner_id
                    vprint(api_endpoint)
                    response = session.get(api_endpoint, headers=api_headers_admin)
                    vprint(response.json())
                    if not 'errcode' in response.json():
                        api_endpoint = api_base + "_synapse/admin/v1/users/" + owner_id + "/login"
                        response = session.post(api_endpoint, headers=api_headers_admin)
                        vprint(response.json())
                        owner_token = response.json()['access_token']
                        api_headers_create =  {"Authorization":"Bearer " + owner_token}
                        vprint(api_headers_create)
                        createroom_usertoken = True
                except:
                    pass

            api_endpoint = api_base + "_matrix/client/v3/createRoom"
            if currentroom['t'] == 'd': # DM, create a private chatroom
                roomname="ZZ-" + "-".join(currentroom['usernames'])
                api_params = {"visibility": "private", "name": roomname, "join_rules": "invite", 'is_direct': 'true'}
            elif currentroom['t'] == 'c': # public chatroom
                roomname=currentroom['name']
                if 'announcement' in currentroom: # there is a topic
                    api_params = {"visibility": "public", "name": roomname, "room_alias_name": roomname, 'topic': currentroom['announcement']}
                else:
                    api_params = {"visibility": "public", "name": roomname, "room_alias_name": roomname}
            elif currentroom['t'] == 'p': # private chatroom
                roomname=currentroom['name']
                if 'announcement' in currentroom: # there is a topic
                    api_params = {"visibility": "private", "join_rules": "invite", "name": roomname, "room_alias_name": roomname, 'topic': currentroom['announcement']}
                else:
                    api_params = {"visibility": "private", "join_rules": "invite", "name": roomname, "room_alias_name": roomname}
            else:
                exit("Unsupported room type : " + currentroom['t'])
            response = session.post(api_endpoint, json=api_params, headers=api_headers_create)
            vprint(response.json())
            if createroom_usertoken:
                api_endpoint_logout = api_base + "/_matrix/client/v3/logout"
                response_logout = session.post(api_endpoint_logout, headers=api_headers_create)
            if response.status_code == 200: # room created successfully
                roomids[currentroom['_id']] = response.json()['room_id'] # map RC_roomID to Matrix_roomID
                cache.write(currentroom['_id'] + "$" + response.json()['room_id'] + "\n")
            elif response.status_code == 400 and response.json()['errcode'] == 'M_ROOM_IN_USE': # room already existing, we search it
                #api_endpoint = api_base + "/_matrix/client/v3/publicRooms"
                api_endpoint = api_base + "_synapse/admin/v1/rooms?search_term=" + roomname
                #api_params = {"filter": { "generic_search_term": roomname}}
                vprint(api_endpoint)
                response = session.get(api_endpoint, headers=api_headers_admin)
                if response.status_code != 200:
                    print("error getting room")
                    print("current room", currentroom)
                    print(response.json())
                    exit(1)
                vprint(response.json())
                found = False
                for room in response.json()['rooms']:
                    if room['name'].lower() == roomname.lower():
                        found = True
                        roomids[currentroom['_id']] = room['room_id'] # map RC_roomID to Matrix_roomID
                        cache.write(currentroom['_id'] + "$" + room['room_id'] + "\n")
                if not found:
                    print("error finding room")
                    print("current room", currentroom)
                    print(response.json())
                    exit(1)
                # roomids[currentroom['_id']] = response.json()['rooms'][0]['room_id'] # map RC_roomID to Matrix_roomID
            else:
                print("current room", currentroom)
                print(response.json())
                exit("Unsupported fail for room creation")
            # rooms.append(json.loads(line))

            # Make old owner admin of this new room
            try:
                api_endpoint = api_base + "_synapse/admin/v1/rooms/" + roomids[currentroom['_id']] + "/make_room_admin"
                api_params = {"user_id": "@" + currentroom['u']['username'] + ":" + args.hostname}
                response = session.post(api_endpoint, json=api_params, headers=api_headers_admin)
                if response.status_code != 200:
                    print("error setting admin")
                    print("current room", currentroom)
                    print(response.json())
                    exit(1)
                vprint(response.json())
            except:
                pass

            # avatar
            if "avatarETag" in currentroom:
                try: # try to find the file in the export
                    api_endpoint = api_base + "_matrix/media/v3/upload?user_id=@" + currentroom['u']['username'] + ":" + args.hostname
                    api_params = {'filename': roomids[currentroom['_id']]}
                    api_headers_file = api_headers_as.copy()
                    # api_headers_file['Content-Type'] = attachment['image_type']
                    localfile=currentroom["avatarETag"]
                    with open(args.inputs + "avatars_rooms/" + localfile, 'rb') as f:
                        # upload as a media to matrix
                        api_headers_file['Content-Type'] = mime.from_file(args.inputs + "avatars_rooms/" + localfile)
                        response = session.post(api_endpoint, json=api_params, headers=api_headers_file, data=f)
                    vprint(response.json())
                    if response.status_code != 200: # Upload problem
                        vprint(response)
                        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), localfile)
                    mxcurl=response.json()['content_uri'] # URI of the uploaded media
                    # Then post a room update referencing this media
                    invite(api_base, api_headers_admin, roomids[currentroom['_id']], '@' + currentroom['u']['username'] + ":" + args.hostname)
                    api_endpoint = api_base + "_matrix/client/v3/rooms/" + roomids[currentroom['_id']] + '/state/m.room.avatar/?user_id=@' + currentroom['u']['username'] + ":" + args.hostname
                    api_params = {"url": mxcurl}
                    response = session.put(api_endpoint, json=api_params, headers=api_headers_as)
                    vprint(response.json())
                    if response.status_code < 200 or response.status_code > 299: #2xx
                        print("error adding avatar for room")
                        print(currentroom)
                        print(response.json())
                        print(response.status_code)
                        exit(1)

                except FileNotFoundError: # We do not have the linked attachment
                    print("Avatar not found for " + roomname + ", in " + localfile)

    cache.close()
    pprint("room ids", roomids)

    # Messages
    print("Importing messages...")
    # We count lines for printing the progress
    nblines = 0
    for line in open(args.inputs + histfile): nblines += 1
    lastts = 0 # last seen timestamp, to check that messages are chronologically sorted
    currentline = 0 # current read line
    idmaps = {} # map RC_messageID to Matrix_messageID for threads, replies, ...

    # load cache
    nbcache = 0
    try:
        with open(messages_cachefile, encoding='utf8') as f:
            for line in f:
                nbcache+=1
                atoms = line.rstrip('\n').split(':')
                idmaps[atoms[0]] = atoms[1]
        f.close()
        print("Restored " + str(nbcache) + " message ids from cache")
    except FileNotFoundError:
        print("No message cache to restore")
    cache = open(messages_cachefile, 'a')

    # print(idmaps)
    # exit(1)

    with open(args.inputs + histfile, 'r') as jsonfile:
        # Each line is a JSON representing a message
        for line in jsonfile:
            currentline+=1
            print("Importing message " + str(currentline) + "/" + str(nblines), end='')
            currentmsg = json.loads(line)
            pprint("current message", currentmsg)
            finished=False # set to true to not (re)print the message in the final step
            response=None
            if currentmsg['rid'] in roomids:
                tgtroom = roomids[currentmsg['rid']] # tgtroom is the matrix room
                tgtuser = "@" + currentmsg['u']['username'] + ":" + args.hostname # tgtuser is the matrix user
                dateTimeObj = datetime.fromisoformat(currentmsg['ts']['$date'])
                tgtts = int(dateTimeObj.timestamp()*1000) # tgtts is the message timestamp
                if tgtts <= int(args.startts): # skip too old message
                    print(", timestamp=" + str(tgtts) + ", skipping")
                    continue
                if currentmsg['_id'] in idmaps:
                    print(", already processed (in cache), skipping")
                    continue
                print(", timestamp=" + str(tgtts))
                if tgtts < lastts: # messages are not sorted, bad things will happen
                    exit("Messages are not sorted, leaving...")
                lastts = tgtts

                # Pinned messages, unhandled
                if 't' in currentmsg and currentmsg['t']=="message_pinned":
                    print(", timestamp=" + str(tgtts) + ", message pinning event, skipping")
                    continue

                # Jitsi start messages, unhandled
                if 't' in currentmsg and currentmsg['t']=="jitsi_call_started":
                   print(", timestamp=" + str(tgtts) + ", jitsi_call event, skipping")
                   continue

                # First, iterate attachments
                # https://developer.rocket.chat/reference/api/rest-api/endpoints/messaging/chat-endpoints/send-message#attachment-field-objects
                if 'attachments' in currentmsg and hasattr(currentmsg['attachments'], '__iter__'):
                    for attachment in currentmsg['attachments']:
                        if 'type' in attachment and attachment['type'] == 'file': # A file
                            vprint("a file")
                            api_endpoint = api_base + "_matrix/media/v3/upload?user_id=" + tgtuser + "&ts=" + str(tgtts)
                            api_params = {'filename': attachment['title']}
                            #files = {'file': open('inputs/files/u5Ga3vn36LCT9bfhW', 'rb')}
                            api_headers_file = api_headers_as.copy()
                            if 'image_type' in attachment: # we have a content-type
                                vprint("an image")
                                api_headers_file['Content-Type'] = attachment['image_type']
                            # elif 'type' in attachment: # other files with a type
                            #     api_headers_file['Content-Type'] = attachment['type']
                            try: # try to find the file in the export
                                localfile=attachment['title_link']
                                localfile=re.sub("/file-upload/", "", localfile)
                                localfile=re.sub("/.*", "", localfile)
                                with open(args.inputs + "files/" + localfile, 'rb') as f:
                                    # upload as a media to matrix
                                    response = session.post(api_endpoint, json=api_params, headers=api_headers_file, data=f)
                                vprint(response.json())
                                if response.status_code != 200: # Upload problem
                                    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), localfile)
                                mxcurl=response.json()['content_uri'] # URI of the uploaded media
                                # Then post a message referencing this media
                                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                                if 'image_type' in attachment: # attachment is an image
                                    api_params = {'msgtype': 'm.image', 'body': attachment['title'], 'url': mxcurl}
                                else: # other files
                                    api_params = {'msgtype': 'm.file', 'body': attachment['title'], 'url': mxcurl}
                                response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                                if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                                    invite(api_base, api_headers_admin, tgtroom, tgtuser)
                                    response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                                if response.status_code != 200:
                                    print("error posting attachment")
                                    print(attachment['title'])
                                    print(response.json())
                                    exit(1)
                                vprint(response.json())
                            except FileNotFoundError: # We do not have the linked attachment
                                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                                api_params = {'msgtype': 'm.text', 'body': "<<< A file named \"" + attachment['title'] + "\" was lost during the migration to Matrix >>>"}
                                response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                                if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                                    invite(api_base, api_headers_admin, tgtroom, tgtuser)
                                    response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                                if response.status_code != 200:
                                    print("error posting missing attachment")
                                    print(attachment['title'])
                                    print(response.json())
                                    exit(1)
                                vprint(response.json())
                            if 'description' in attachment: # Matrix does not support descriptions, we post as a message
                                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                                api_params = {'msgtype': 'm.text', 'body': attachment['description']}
                                response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                                if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                                    invite(api_base, api_headers_admin, tgtroom, tgtuser)
                                    response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                                if response.status_code != 200:
                                    print("error posting description")
                                    print(attachment['description'])
                                    print(response.json())
                                    exit(1)
                                vprint(response.json())

                        elif 'message_link' in attachment: # This is a citation
                            vprint("A citation")
                            if 'msg' in currentmsg:
                                textmsg = emoji.emojize(currentmsg['msg'], language='alias')
                            else:
                                textmsg = ""
                            html = markdown.markdown(textmsg) # render the markdown
                            related = re.sub(".*\?msg=", "", attachment['message_link']) # find related Matrix_messageID
                            api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                            if related in idmaps:
                                api_params = {'msgtype': 'm.text', 'body': "> <" + attachment['author_name'] + ">" + attachment['text'] + "\n\n" + textmsg,
                                    "format": "org.matrix.custom.html",
                                    "formatted_body": "<mx-reply><blockquote>In reply to " + attachment['author_name'] + "<br>" + attachment['text'] + "</blockquote></mx-reply>" + html,
                                    "m.relates_to": {
                                        "m.in_reply_to": {
                                            "event_id": idmaps[related]
                                            }
                                        }}
                            else:
                                api_params = {'msgtype': 'm.text', 'body': "> <" + attachment['author_name'] + ">" + attachment['text'] + "\n\n" + textmsg,
                                    "format": "org.matrix.custom.html",
                                    "formatted_body": "<mx-reply><blockquote>In reply to " + attachment['author_name'] + "<br>" + attachment['text'] + "</blockquote></mx-reply>" + html,
                                    }
                            response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                            if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                                invite(api_base, api_headers_admin, tgtroom, tgtuser)
                                response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                            if response.status_code != 200:
                                print("error posting related")
                                print(textmsg)
                                print(response.json())
                                exit(1)
                            vprint(response.json())
                            finished=True # do not repost this message in the final step
                        elif 'image_url' in attachment: # This is an external image
                            vprint("An external image")
                            api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                            api_params = {'msgtype': 'm.text', 'body': attachment['image_url']}
                            response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                            if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                                invite(api_base, api_headers_admin, tgtroom, tgtuser)
                                response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                            if response.status_code != 200:
                                print("error posting image url")
                                print(attachment['image_url'])
                                print(response.json())
                                exit(1)
                            vprint(response.json())
                        else:
                            exit("Unsupported attachment : " + str(attachment))

                # Finally post the message
                if 'msg' in currentmsg:
                    if currentmsg['msg'] != "" and not finished:
                        api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                        api_params = format_message(emoji.emojize(currentmsg['msg'], language='alias'))
                        response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                        vprint(response.json())

                        if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                            invite(api_base, api_headers_admin, tgtroom, tgtuser)
                            response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                            vprint(response.json())

                        if response.status_code != 200:
                            print("error posting message")
                            print(currentmsg['msg'])
                            print(response.json())
                            exit(1)

                # We keep track of messageIDs to link future references
                if response is not None: # is None if no message has been posted, nothing to keep in idmaps in this case
                    idmaps[currentmsg['_id']]=response.json()['event_id']
                    cache.write(currentmsg['_id'] + ":" + response.json()['event_id'] + "\n")
                else:
                    vprint("No response to get an event_id from")
                    continue

                if 'reactions' in currentmsg:
                    for reaction in currentmsg['reactions']:
                        tgtreaction = emoji.emojize(reaction, language='alias')
                        for username in currentmsg['reactions'][reaction]['usernames']:
                            tgtusername = "@" + username + ":" + args.hostname
                            vprint(tgtusername + ":" + tgtreaction)
                            api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.reaction?user_id=' + tgtusername + "&ts=" + str(tgtts)
                            api_params = {"m.relates_to": {
                                                "event_id": idmaps[currentmsg['_id']],
                                                "key": tgtreaction,
                                                "rel_type": "m.annotation"
                                                }}
                            response = session.post(api_endpoint, json=api_params, headers=api_headers_as)
                            vprint(response.json())
            else:
                exit("not in a room")

    cache.close()
