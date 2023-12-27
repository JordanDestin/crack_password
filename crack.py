#!/usr/bin/env python3
import argparse
import hashlib
import string
import sys
import time
import  atexit


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


def display_time():
    print("Durée : " + str(time.time() - start) + " secondes")


parser = argparse.ArgumentParser(description="Password Cracker")
parser.add_argument("-f", "--file", dest="file", help="Path of the dictionary", required=False)
parser.add_argument("-g", "--gen", dest="gen", help="Generate Md5 has of password", required=False)
parser.add_argument("-md5", dest="md5", help="Hashed password (MD5)", required=False)
parser.add_argument("-l", dest="plength", help="Password length", required=False, type=int)

args = parser.parse_args()

start = time.time()
atexit.register(display_time)

if args.md5:
    print("cracking hash" + args.md5)
    if args.file and not args.plength:
        print("using dictionary file" + args.file)
        crack_dict(args.md5, args.file)
    elif args.plength and not args.file:
        print("using incremental  mode for" + str(args.plength))
        crack_inc(args.md5, args.plength)
    else:
        print("please choose either -f or -l argument")
else:
    print("MD5 has not provided")

if args.gen:
    print("[MD5 HASH OF " + args.gen + " : " + hashlib.md5(args.gen.encode("utf8")).hexdigest())
