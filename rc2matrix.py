#!/usr/bin/python3

import argparse
import sys
import os
import pprint as ppprint
import json
import requests

# globals
# inputs = "inputs/"
roomsfile = "rocketchat_room.json"
histfile = "rocketchat_message.json"
verbose = False

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

def createArgParser():
    parser = argparse.ArgumentParser(description='Launches RC2Matrix migration')
    parser.add_argument("-i", type=str, help='inputs folder, defaults to inputs/', dest="inputs", default="inputs/")
    parser.add_argument("-n", type=str, help='Matrix server', dest="hostname", default="localhost")
    parser.add_argument("-u", type=str, help='Admin username', dest="username", default="admin")
    parser.add_argument("-p", type=str, help='Admin password', dest="password", default="password")
    parser.add_argument("-t", type=str, help='Admin token', dest="token", default=None )
    parser.add_argument("-v", help='verbose', dest="verbose", action="store_true")

    return parser



if __name__ == '__main__':
    parser = createArgParser()
    args = parser.parse_args()
    verbose = args.verbose

    if (verbose):
        print("Arguments are: ", args)

    api_base = args.hostname + "/"
    # Connect to matrix
    if args.token is None: # create a token
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

    api_headers =  {"Authorization":"Bearer " + args.token}

    # Rooms
    roomnames = {}
    roomids = {}
    with open(args.inputs + roomsfile, 'r') as jsonfile:
        for line in jsonfile:
            currentroom = json.loads(line)
            pprint("current room", currentroom)
            if 'name' in currentroom:
                roomname=currentroom['name']
                roomnames[currentroom['_id']] = roomname
            else:
                roomname=currentroom['_id']
            api_endpoint = api_base + "_matrix/client/v3/createRoom"
            api_params = {"visibility": "public", "name": roomname, "room_alias_name": roomname}
            response = requests.post(api_endpoint, json=api_params, headers=api_headers)
            vprint(response.json())
            roomids[currentroom['_id']] = response.json()['room_id']
            # rooms.append(json.loads(line))

    pprint("room names", roomnames)
    pprint("room ids", roomids)


    # Messages
    with open(args.inputs + histfile, 'r') as jsonfile:
        for line in jsonfile:
            currentmsg = json.loads(line)
            pprint("current message", currentmsg)
            if currentmsg['rid'] in roomids:
                tgtroom = roomids[currentmsg['rid']]
                vprint("should be in room " + str(tgtroom))
                api_endpoint = api_base + "_matrix/client/v3/rooms/" + tgtroom + '/send/m.room.message?ts=33245444/?ts=33245444'
                api_params = {'origin_server_ts': '33245554', 'ts': '33245554', 'msgtype': 'm.text', 'body': 'b' + currentmsg['msg']}
                response = requests.post(api_endpoint, json=api_params, headers=api_headers)
                vprint(response.json())
            else:
                vprint("not in a room")

# , "event_id": "$143273582443PhrSn:example.org", "origin_server_ts": 1432735824653,  "room_id": "!jEsUZKDJdhlrceRyVU:example.org", "sender": "@example:example.org", "type": "m.room.message", "unsigned": {    "age": 1234  }

#
#
# access_token = 'YOURveryLONGaccessTOKENhere'
# room_id = '!ZkngAyfszzfCqwNZUd:phys:phys.ethz.ch'
# url = 'https://matrix.phys.ethz.ch/_matrix/client/r0/rooms/' + room_id + '/send/m.room.message'
# headers = {'Authorization': ' '.join(['Bearer', access_token])}
# data = {
#     'body': 'hello matrix',
#     'format': 'org.matrix.custom.html',
#     'formatted_body': 'hello <b>matrix</b>',
#     'msgtype': 'm.text'
# }
#
# r = requests.post(url, json=data, headers=headers)


# {
#   "content": {
#     "body": "This is an example text message",
#     "format": "org.matrix.custom.html",
#     "formatted_body": "<b>This is an example text message</b>",
#     "msgtype": "m.text"
#   },
#   "event_id": "$143273582443PhrSn:example.org",
#   "origin_server_ts": 1432735824653,
#   "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
#   "sender": "@example:example.org",
#   "type": "m.room.message",
#   "unsigned": {
#     "age": 1234
#   }
# }
