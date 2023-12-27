#!/usr/bin/env python3
import argparse
import hashlib
import string
import sys
import time
import atexit
import urllib.request
import urllib.response
import urllib.error


def crack_dict(md5, file):
    try:
        trouve = False
        ofile = open(file, "r")
        for mot in ofile.readlines():
            mot = mot.strip("\n").encode("utf8")
            hashmd5 = hashlib.md5(mot).hexdigest()
            if hashmd5 == md5:
                print("mot de passe trouvé : " + str(mot))
                trouve = True
        if not trouve:
            print("mot de passe non trouvé")
        ofile.close()
    except FileNotFoundError:
        print("erreur fichier")
        sys.exit(1)
    except Exception as err:
        print("Erreur : " + str(err))
        sys.exit(2)


def crack_inc(md5, length, currpass=[]):
    lettres = string.printable

    if length >= 1:
        if len(currpass) == 0:
            currpass = ['a' for  _ in range(length)]
            crack_inc(md5, length, currpass)
        else:
            for c in lettres:
                currpass[length -1] = c
                currhash = hashlib.md5("".join(currpass).encode("utf8")).hexdigest()
                print("Trying : " + "".join(currpass) + "("+currhash+")")
                if currhash == md5:
                    print("Password found! " + "".join(currpass))
                    sys.exit(0)
                else:
                    crack_inc(md5, length -1, currpass)

def crack_online(md5):
    try:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"
        headers = {"User-Agent": user_agent}
        url = "https://www.googlr.fr/search?hl=fr&q=" + md5
        request = urllib.request.Request(url, None, headers)
        response = urllib.request.urlopen(request)
    except urllib.error.HTTPError as e:
        print("Http error: " + e.code)
    except urllib.error.URLError as e:
        print("Error Url: " + e.reason)

    if "No result" in str(response.read()):
        print("no find hash")
    else:
        print("Hash find: " + url)


def show_time():
    print("Durée : " + str(time.time() - start) + " secondes")


parser = argparse.ArgumentParser(description="Password Cracker")
parser.add_argument("-f", "--file", dest="file", help="Path of the dictionary", required=False)
parser.add_argument("-g", "--gen", dest="gen", help="Generate Md5 has of password", required=False)
parser.add_argument("-md5", dest="md5", help="Hashed password (MD5)", required=False)
parser.add_argument("-l", dest="plength", help="Password length", required=False, type=int)
parser.add_argument("-ol", dest="online", help="search hash online", required=False, action="store_true")

args = parser.parse_args()

start = time.time()
atexit.register(show_time)

if args.md5:
    print("cracking hash" + args.md5)
    if args.file and not args.plength:
        print("using dictionary file" + args.file)
        crack_dict(args.md5, args.file)
    elif args.plength and not args.file:
        print("using incremental  mode for" + str(args.plength))
        crack_inc(args.md5, args.plength)
    elif args.online:
        print("using online mode")
        crack_online(args.md5)
    else:
        print("please choose either -f or -l argument")
else:
    print("MD5 has not provided")

if args.gen:
    print("[MD5 HASH OF " + args.gen + " : " + hashlib.md5(args.gen.encode("utf8")).hexdigest())
