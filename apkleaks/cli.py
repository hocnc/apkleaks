#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path
import shutil
import pkg_resources
import subprocess
from apkleaks.apkleaks import APKLeaks
from apkleaks.colors import color as col

def header():
	try:
		VERSION = "v" + pkg_resources.require("apkleaks")[0].version
	except Exception:
		VERSION = open(os.path.join(str(Path(__file__).parent.parent), "VERSION"), "r").read().strip()
	print(col.HEADER + "     _    ____  _  ___               _        \n    / \\  |  _ \\| |/ / |    ___  __ _| | _____ \n   / _ \\ | |_) | ' /| |   / _ \\/ _` | |/ / __|\n  / ___ \\|  __/| . \\| |__|  __/ (_| |   <\\__ \\\n /_/   \\_\\_|   |_|\\_\\_____\\___|\\__,_|_|\\_\\___/\n {}\n --\n Scanning APK file for URIs, endpoints & secrets\n (c) 2020-2021, dwisiswant0\n".format(VERSION) + col.ENDC, file=sys.stderr)

def argument():
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--folder", help="Folder to scanning", type=str, required=False)
	parser.add_argument("-f", "--file", help="APK file to scanning", type=str, required=False)
	parser.add_argument("-o", "--output", help="Write to file results (random if not set)", type=str, required=False)
	parser.add_argument("-p", "--pattern", help="Path to custom patterns JSON", type=str, required=False)
	parser.add_argument("-a", "--args", help="Disassembler arguments (e.g. --threads-count 5 --deobf)", type=str, required=False)
	parser.add_argument("--json", help="Save as JSON format", required=False, action="store_true")
	parser.add_argument("-l", "--list", help="List Packages", action='store_true', required=False)
	parser.add_argument("-pkg", "--package", help="Package Name", type=str, required=False)
	arg = parser.parse_args()
	return arg


def getAPKPathsForPackage(pkgname):
	print("Getting APK path(s) for package: " + pkgname)
	paths = []
	proc = subprocess.run(["adb", "shell", "pm", "path", pkgname], stdout=subprocess.PIPE)
	if proc.returncode != 0:
		print("Error: Failed to run 'adb shell pm path " + pkgname + "'.")
		sys.exit(1)
	out = proc.stdout.decode("utf-8")
	for line in out.split(os.linesep):
		if line.startswith("package:"):
			line = line[8:].strip()
			print("[+] APK path: " + line)
			paths.append(line)
	print("")
	return paths

def checkDependencies():
	deps = ["apktool"]
	missing = []
	for dep in deps:
		if shutil.which(dep) is None:
			missing.append(dep)
	if len(missing) > 0:
		print("Error, missing dependencies, ensure the following commands are available on the PATH: " + (", ".join(missing)))
		sys.exit(1)

def getTargetAPK(apkpaths):
    for remotepath in apkpaths:
        command = ["adb", "pull", remotepath]
        ret = subprocess.run(command)
        if ret.returncode != 0:
            print("Error: Failed to run 'adb shell pull'")
            sys.exit(1) 

def listPackages():
    command = ["adb", "shell", "pm", "list","packages"]
    ret = subprocess.run(command)
    if ret.returncode != 0:
        print("Error: Failed to run 'mkdir'")
        sys.exit(1) 


def main():
	header()
	args = argument()
	init = APKLeaks(args)

	if args.list:
		listPackages()
	elif args.package:
		apkpaths = getAPKPathsForPackage(args.package)
		getTargetAPK(apkpaths)
	elif init.folder:
		init.scanning_folder()
		init.cleanup()
	elif init.file:
		checkDependencies()
		init.decompile()
		init.scanning()
		init.cleanup()
		

		