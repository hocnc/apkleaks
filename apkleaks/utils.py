#!/usr/bin/env python3
import os
import re
import sys
from apkleaks.colors import color as col

filepath=''
word_blacklist = [b'schemas.android.com',b'www.example.com',b'aomedia.org',b'schema.org',b'play.google.com',b'update.crashlytics.com',b'adobe.com',b'Ljava',b'www.w3.org',b'www.googleapis.com',b'webkit.org',b'developer.mozilla.org',b'drafts.csswg.org']
filepath_blacklist = [os.path.join(filepath,"res","layout").encode(), \
	os.path.join(filepath,"res","animator").encode(), \
	os.path.join(filepath,"res","color").encode(), \
	os.path.join(filepath,"res","drawable").encode(), \
	os.path.join(filepath,"res","font").encode(), \
	os.path.join(filepath,"res","menu").encode(), \
	os.path.join(filepath,"smali","com","google").encode(), \
		b'.ttf',b'.wav',b'.png',b'.mp3']
class util:
	@staticmethod
	def write(message, color):
		sys.stdout.write("%s%s%s" % (color, message, col.ENDC))

	@staticmethod
	def writeln(message, color):
		util.write(message + "\n", color)

	@staticmethod
	def finder(pattern, path):
		matcher = re.compile(pattern)
		found = {}
		for fp, _, files in os.walk(path):
			for fn in files:
				filepath = os.path.join(fp, fn)
				if any(path in filepath.encode() for path in filepath_blacklist):
					continue
				with open(filepath,'rb') as handle:
					text_lines = handle.readlines()
					for line_number, line in enumerate(text_lines):
						for mo in matcher.finditer(line):
							if any(word in mo.group(0) for word in word_blacklist):
								continue
							found.setdefault(mo.group(0),[]).append([filepath,line_number+1,mo.start(0)])# filepath,linenumber,start
		return found
