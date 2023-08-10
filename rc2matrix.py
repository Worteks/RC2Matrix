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


# globals
roomsfile = "rocketchat_room.json"
usersfile = "users.json"
histfile = "rocketchat_message.json"
verbose = False

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

if __name__ == '__main__':
    parser = createArgParser()
    args = parser.parse_args()
    verbose = args.verbose

    if (verbose):
        print("Arguments are: ", args)

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

    # Import rooms
    print("Importing rooms...")
    roomids = {}  # Map RC_roomID to Matrix_roomID
    with open(args.inputs + roomsfile, 'r') as jsonfile:
        # Each line is a JSON representing a RC room
        for line in jsonfile:
            currentroom = json.loads(line)
            pprint("current room", currentroom)
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
            response = requests.post(api_endpoint, json=api_params, headers=api_headers_admin)
            vprint(response.json())
            if response.status_code == 200: # room created successfully
                roomids[currentroom['_id']] = response.json()['room_id'] # map RC_roomID to Matrix_roomID
            elif response.status_code == 400 and response.json()['errcode'] == 'M_ROOM_IN_USE': # room already existing, we search it
                #api_endpoint = api_base + "/_matrix/client/v3/publicRooms"
                api_endpoint = api_base + "/_synapse/admin/v1/rooms?search_term=" + roomname
                #api_params = {"filter": { "generic_search_term": roomname}}
                response = requests.get(api_endpoint, headers=api_headers_admin)
                vprint(response.json())
                roomids[currentroom['_id']] = response.json()['rooms'][0]['room_id'] # map RC_roomID to Matrix_roomID
            else:
                exit("Unsupported fail for room creation")
            # rooms.append(json.loads(line))

    pprint("room ids", roomids)

    # Import users
    print("Importing users...")
    with open(args.inputs + usersfile, 'r') as jsonfile:
        # Each line is a JSON representing a RC user
        for line in jsonfile:
            currentuser = json.loads(line)
            pprint("current user", currentuser)
            username=currentuser['username']
            # matrix username will be @username:server
            api_endpoint = api_base + "/_synapse/admin/v2/users/@" + username + ":" + args.hostname
            api_params = {"admin": False}
            response = requests.put(api_endpoint, json=api_params, headers=api_headers_admin)
            vprint(response.json())


    # Messages
    print("Importing messages...")
    # We count lines for printing the progress
    nblines = 0
    for line in open(args.inputs + histfile): nblines += 1
    lastts = 0 # last seen timestamp, to check that messages are chronologically sorted
    currentline = 0 # current read line
    idmaps = {} # map RC_messageID to Matrix_messageID for threads, replies, ...
    with open(args.inputs + histfile, 'r') as jsonfile:
        # Each line is a JSON representing a message
        for line in jsonfile:
            currentline+=1
            print("Importing message " + str(currentline) + "/" + str(nblines))
            currentmsg = json.loads(line)
            pprint("current message", currentmsg)
            finished=False # set to true to not (re)print the message in the final step
            if currentmsg['rid'] in roomids:
                tgtroom = roomids[currentmsg['rid']] # tgtroom is the matrix room
                tgtuser = "@" + currentmsg['u']['username'] + ":" + args.hostname # tgtuser is the matrix user
                dateTimeObj = datetime.fromisoformat(currentmsg['ts']['$date'])
                tgtts = int(dateTimeObj.timestamp()*1000) # tgtts is the message timestamp
                if tgtts < lastts: # messages are not sorted, bad things will happen
                    exit("Messages are not sorted, leaving...")
                lastts = tgtts
                # First, iterate attachments
                if 'attachments' in currentmsg:
                    for attachment in currentmsg['attachments']:
                        if 'type' in attachment and attachment['type'] == 'file': # A file
                            vprint("a file")
                            api_endpoint = api_base + "/_matrix/media/v3/upload?user_id=" + tgtuser + "&ts=" + str(tgtts)
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
                                with open("inputs/files/" + localfile, 'rb') as f:
                                    # upload as a media to matrix
                                    response = requests.post(api_endpoint, json=api_params, headers=api_headers_file, data=f)
                                vprint(response.json())
                                mxcurl=response.json()['content_uri'] # URI of the uploaded media
                                # Then post a message referencing this media
                                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                                if 'image_type' in attachment: # attachment is an image
                                    api_params = {'msgtype': 'm.image', 'body': attachment['title'], 'url': mxcurl}
                                else: # other files
                                    api_params = {'msgtype': 'm.file', 'body': attachment['title'], 'url': mxcurl}
                                response = requests.post(api_endpoint, json=api_params, headers=api_headers_as)
                                vprint(response.json())
                            except FileNotFoundError: # We do not have the linked attachment
                                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                                api_params = {'msgtype': 'm.text', 'body': "<<< A file named \"" + attachment['title'] + "\" was lost during the migration to Matrix >>>"}
                                response = requests.post(api_endpoint, json=api_params, headers=api_headers_as)
                                vprint(response.json())
                            if 'description' in attachment: # Matrix does not support descriptions, we post as a message
                                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                                api_params = {'msgtype': 'm.text', 'body': attachment['description']}
                                response = requests.post(api_endpoint, json=api_params, headers=api_headers_as)
                                vprint(response.json())

                        elif 'message_link' in attachment: # This is a citation
                            vprint("A citation")
                            html = markdown.markdown(currentmsg['msg']) # render the markdown
                            related = re.sub(".*\?msg=", "", attachment['message_link']) # find related Matrix_messageID
                            api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                            api_params = {'msgtype': 'm.text', 'body': "> <" + attachment['author_name'] + ">" + attachment['text'] + "\n\n" + currentmsg['msg'],
                                "format": "org.matrix.custom.html",
                                "formatted_body": "<mx-reply><blockquote>In reply to " + attachment['author_name'] + "<br>" + attachment['text'] + "</blockquote></mx-reply>" + html,
                                "m.relates_to": {
                                    "m.in_reply_to": {
                                        "event_id": idmaps[related]
                                        }
                                    }}
                            response = requests.post(api_endpoint, json=api_params, headers=api_headers_as)
                            vprint(response.json())
                            finished=True # do not repost this message in the final step
                        else:
                            exit("Unsupported attachment")

                # Finally post the message
                if currentmsg['msg'] != "" and not finished:
                    api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                    api_params = format_message(currentmsg['msg'])
                    response = requests.post(api_endpoint, json=api_params, headers=api_headers_as)
                    vprint(response.json())

                if response.status_code == 403 and response.json()['errcode'] == 'M_FORBIDDEN': # not in the room
                    # Join room : invite then join
                    api_endpoint = api_base + "/_synapse/admin/v1/join/" + tgtroom
                    api_params = {'user_id': tgtuser}
                    response = requests.post(api_endpoint, json=api_params, headers=api_headers_admin)
                    vprint(response.json())

                    # Repost message
                    api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?user_id=' + tgtuser + "&ts=" + str(tgtts) # ts, ?user_id=@_irc_user:example.org
                    api_params = format_message(currentmsg['msg'])
                    response = requests.post(api_endpoint, json=api_params, headers=api_headers_as)
                    vprint(response.json())

                # We keep track of messageIDs to link future references
                idmaps[currentmsg['_id']]=response.json()['event_id']
            else:
                exit("not in a room")
