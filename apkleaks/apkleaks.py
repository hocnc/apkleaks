#!/usr/bin/env python3
import io
import json
import logging.config
import os
import re
import shutil
import sys
import tempfile
import threading

from contextlib import closing
from distutils.spawn import find_executable
from pathlib import Path
from pipes import quote
from urllib.request import urlopen
from urllib.error import *
from zipfile import ZipFile

from pyaxmlparser import APK

from apkleaks.colors import color as col
from apkleaks.utils import util

class APKLeaks:
	def __init__(self, args):
		self.apk = None
		self.folder = args.folder
		self.file = args.file
		self.json = args.json
		self.disarg = args.args
		self.prefix = "apkleaks-"
		#self.tempdir = tempfile.mkdtemp(prefix=self.prefix)
		self.main_dir = os.path.dirname(os.path.realpath(__file__))
		self.output = tempfile.mkstemp(suffix=".%s" % ("json" if self.json else "txt"), prefix=self.prefix)[1] if args.output is None else args.output
		self.fileout = open(self.output, "wb")
		self.pattern = os.path.join(str(Path(self.main_dir).parent), "config", "regexes.json") if args.pattern is None else args.pattern
		self.out_json = {}
		self.scanned = False
		logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})

	def apk_info(self):
		return APK(self.file)


	def decompile(self):
		if os.path.exists(self.file[:-4]):
			util.writeln("** Decompiled APK...", col.FAIL)
			return
		util.writeln("** Decompiling APK...", col.OKBLUE)
		args = ["apktool", "d",self.file,"-o",self.file[:-4],"-f"]
		try:
			args.extend(re.split(r"\s|=", self.disarg))
		except Exception:
			pass
		comm = "%s" % (" ".join(quote(arg) for arg in args))
		comm = comm.replace("\'","\"")

		os.system(comm)

	def detect_firebase(self,secret):
		url = 'https://' + secret + '/.json'
		try:
			response = urlopen(url)
		except HTTPError as err:
			if(err.code==401):
				print("Secure Firbase Instance Found: "+ url + '\n')
				self.fileout.write(b"%b" % (b"Secure Firbase Instance Found: " + url.encode() + b"\n" if self.json is False else b""))
				return
			if(err.code==404):
				print("Project does not exist: "+ url+ '\n')
				self.fileout.write(b"%b" % (b"Project does not exist: " + url.encode() + b"\n" if self.json is False else b""))
				return     
			else:
				print("Unable to identify misconfiguration for: " + url+ '\n')
				self.fileout.write(b"%b" % (b"Unable to identify misconfiguration for: " + url.encode() + b"\n" if self.json is False else b""))
				return
		except URLError as err:
			print("Facing connectivity issues. Please Check the Network Connectivity and Try Again."+ '\n')
			return
		print("Misconfigured Firbase Instance Found: "+ url+ '\n')
		self.fileout.write(b"%b" % (b"Misconfigured Firbase Instance Found: " + url.encode() + b"\n" if self.json is False else b""))


	def extract(self, name, matches):
		if len(matches):
			stdout = ("[%s]" % (name))
			util.writeln("\n" + stdout, col.OKGREEN)
			self.fileout.write(b"%b" % (stdout.encode() + b"\n" if self.json is False else b""))
			for secret in matches:
				#print(secret)
				#FILEPATH
				for filepath in matches[secret]:
					print('%s:%d:%d'%(filepath[0],filepath[1],filepath[2]))
				if name == "LinkFinder":
					if re.match(rb"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video).*\/.+", secret) is not None:
						continue
					secret = secret[len("'"):-len("'")]
				
				if name == "Firebase":
					self.detect_firebase(secret.decode('latin-1'))
					continue

				
				print(secret.decode('latin-1')+'\n')
				self.fileout.write(b"%b" % (secret + b"\n" if self.json is False else b""))
			self.fileout.write(b"%b" % (b"\n" if self.json is False else b""))
			self.out_json["results"].append({"name": name, "matches": matches})
			self.scanned = True

	def scanning(self):
		self.apk = self.apk_info()
		if self.apk is None:
			sys.exit(util.writeln("** Undefined package. Exit!", col.FAIL))
		util.writeln("\n** Scanning against '%s'" % (self.apk.package), col.OKBLUE)
		self.out_json["package"] = self.apk.package
		self.out_json["results"] = []
		with open(self.pattern) as regexes:
			regex = json.load(regexes)
			for name, pattern in regex.items():
				if isinstance(pattern, list):
					for p in pattern:
						try:
							thread = threading.Thread(target = self.extract, args = (name, util.finder(p.encode(), self.file[:-4])))
							thread.start()
							thread.join()
						except KeyboardInterrupt:
							sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))
				else:
					try:
						thread = threading.Thread(target = self.extract, args = (name, util.finder(pattern.encode(), self.file[:-4])))
						thread.start()
						thread.join()
					except KeyboardInterrupt:
						sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

	def scanning_folder(self):
		util.writeln("\n** Scanning against '%s'" % (self.folder), col.OKBLUE)
		self.out_json["folder"] = self.folder
		self.out_json["results"] = []
		with open(self.pattern) as regexes:
			regex = json.load(regexes)
			for name, pattern in regex.items():
				if isinstance(pattern, list):
					for p in pattern:
						try:
							thread = threading.Thread(target = self.extract, args = (name, util.finder(p.encode(), self.folder)))
							thread.start()
							thread.join()
						except KeyboardInterrupt:
							sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))
				else:
					try:
						thread = threading.Thread(target = self.extract, args = (name, util.finder(pattern.encode(), self.folder)))
						thread.start()
						thread.join()
					except KeyboardInterrupt:
						sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

	def cleanup(self):
		#shutil.rmtree(self.tempdir)
		if self.scanned:
			self.fileout.write(b"%b" % (json.dumps(self.out_json, indent=4).encode() if self.json else b""))
			self.fileout.close()
			print("%s\n** Results saved into '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.output, col.HEADER, col.ENDC))
		else:
			self.fileout.close()
			os.remove(self.output)
			util.writeln("\n** Done with nothing. ¯\\_(ツ)_/¯", col.WARNING)
