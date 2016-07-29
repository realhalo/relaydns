#!/usr/bin/env python

'''
[narrowcast] narrowcast-cli.py :: chat-over-dns using relaydns. (debugging version)
Copyright (C) 2016 fakehalo [v9@fakehalo.us]

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
'''

'''

EXPRESSION:
	VALUE.KEY.relaydns.com

HELPER FUNCTIONS:
	SECOND_WINDOW := FLOOR(UNIX_TIMESTAMP / FREQUENCY)

LOGIC:
	KEY := DNS_LABELIZE(BASE64(AES_ECB(SHA256(INCREMENT + SECOND_WINDOW() + FREQUENCY + CHANNEL), SHA256(CHANNEL))))
	VALUE := DNS_LABELIZE(BASE64(AES_ECB(32_BYTES_OF_DATA_MAX, SHA256(CHANNEL))))

NOTES:
	since ECB is used for our mode (as predictability is required), we must not have predictable data.
'''

import os
import sys
import getopt
import time
import base64
import hashlib
import dns.resolver # pip install dnspython
from Crypto.Cipher import AES # pip install pycrypto

NARROWCAST_AES_PADDING = '\x00'
NARROWCAST_AES_BLOCKSIZE = AES.block_size
NARROWCAST_TEXT_BLOCKSIZE = 32
NARROWCAST_BASE64_REMAP = [('=','-0'), ('/','-1'), ('+','-2')]
NARROWCAST_BASE64_LPAD = '0-'
NARROWCAST_BASE_PAD = '_'
NARROWCAST_BASE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" # base62 alphabet
NARROWCAST_CONF = {
	"dns_server": None,
	"channel": None,
	"frequency": 300, # 5 minute default
	"domain": 'relaydns.com',
	"push": None,
	"file": None
}
NARROWCAST_CURRENT_ID = {
	"timestamp": 0,
	"increment": 0
}

# id used to reference the current key (general time segment + channel + increment)
def narrowcast_current_id():
	ts = narrowcast_current_segment_time()
	# reset the increment if the timestamp changed.
	if ts != NARROWCAST_CURRENT_ID['timestamp']:
		NARROWCAST_CURRENT_ID['timestamp'] = ts
		NARROWCAST_CURRENT_ID['increment'] = 0
	return str(NARROWCAST_CURRENT_ID['increment']) + str(ts) + str(NARROWCAST_CONF['frequency']) + NARROWCAST_CONF['channel'];

# after a push or read we must increment our key.
def narrowcast_current_id_inc():
	NARROWCAST_CURRENT_ID['increment'] += 1

# hash version of narrowcast_current_id()
def narrowcast_current_id_hash():
	return hashlib.sha256(narrowcast_current_id()).digest()

# hash version of channel
def narrowcast_channel_hash():
	return hashlib.sha256(NARROWCAST_CONF['channel']).digest()

# break unixtime down to static time periods.  (ie. 1453328290 / 900 = 1614809, evetything within that 900 second window falls within 1614809)
def narrowcast_current_segment_time():
	return int(time.time() / NARROWCAST_CONF['frequency'])

# pad AES. (16 byte blocksize)
def narrowcast_encode_pad(str):
	return str + ((NARROWCAST_AES_BLOCKSIZE - len(str)) % NARROWCAST_AES_BLOCKSIZE) * NARROWCAST_AES_PADDING;

# convert bytes to dns segment.  (encrypt + base64 + replace incompatible base64 characters to dns segment)
def narrowcast_encode_segment(str, cipher):
	enc = base64.b64encode(cipher.encrypt(narrowcast_encode_pad(str)))
	for f,t in NARROWCAST_BASE64_REMAP:
		enc = enc.replace(f, t)

	# special left padding for the beginning of a segment, can't start with a dash.
	if enc[0] == '-':
		enc = NARROWCAST_BASE64_LPAD + enc
	return enc

# convert dns segment to bytes.  (replace incompatible base64 characters - base64 - decrypt)
def narrowcast_decode_segment(str, cipher):
	dec = str
	for f,t in NARROWCAST_BASE64_REMAP:
		dec = dec.replace(t, f)

	# special left padding for the beginning of a segment, remove the dash padding.
	if dec[0:len(NARROWCAST_BASE64_LPAD)] == NARROWCAST_BASE64_LPAD:
		dec = dec[len(NARROWCAST_BASE64_LPAD):]
	try:
		return cipher.decrypt(base64.b64decode(dec)).rstrip(NARROWCAST_AES_PADDING)
	except:
		return "[DECRYPT_FAILED]"

# general usage.
def narrowcast_usage(progname):
	print "syntax: " + progname + " -c channel [-f frequency] [-s dns_server] [-p text] [-f file] [-d domain]"
	sys.exit(0)

# handle command-line arguments.
def narrowcast_getopt(argv):
	try:
		opts, args = getopt.getopt(argv[1:], 'c:f:s:p:d:F:h', ['channel=', 'frequency=', 'server=', 'push=', 'filepush=', 'domain=', 'help'])
	except getopt.GetoptError:
		narrowcast_usage(argv[0])
	for opt, arg in opts:
		if opt in ('-c', '--channel'):
			NARROWCAST_CONF['channel'] = arg
		elif opt in ('-s', '--server'):
			NARROWCAST_CONF['dns_server'] = arg
		elif opt in ('-f', '--frequency'):
			NARROWCAST_CONF['frequency'] = int(arg)
		elif opt in ('-d', '--domain'):
			NARROWCAST_CONF['domain'] = arg
		elif opt in ('-p', '--push'):
			NARROWCAST_CONF['push'] = arg
		elif opt in ('-F', '--filepush'):
			NARROWCAST_CONF['file'] = arg
		else:
			narrowcast_usage(argv[0])

# MAIN
if __name__ == "__main__":
	narrowcast_getopt(sys.argv)

	assert NARROWCAST_CONF['channel'] is not None, "No channel specified!"

	print "Server:", NARROWCAST_CONF['dns_server']
	print "Channel:", NARROWCAST_CONF['channel']
	print "Frequency:", NARROWCAST_CONF['frequency']
	print "Push:", NARROWCAST_CONF['push']

	#cipher = AES.new(NARROWCAST_CONF['channel'], AES.MODE_ECB) # ECB needs to be used for predictability, a catch 22.
	cipher = AES.new(narrowcast_channel_hash(), AES.MODE_ECB) # ECB needs to be used for predictability, a catch 22.
	resolver = dns.resolver.Resolver()

	if NARROWCAST_CONF['file'] is not None:
		with open(NARROWCAST_CONF['file'], 'r') as f:
			NARROWCAST_CONF['push'] = f.read()

	if NARROWCAST_CONF['dns_server'] is not None:
		resolver.nameservers = [NARROWCAST_CONF['dns_server']]

	# push mode: break --push command-line data into 31-byte segments to be encoded.
	if NARROWCAST_CONF['push'] is not None:
		segments = [NARROWCAST_CONF['push'][i:i+NARROWCAST_TEXT_BLOCKSIZE] for i in range(0, len(NARROWCAST_CONF['push']), NARROWCAST_TEXT_BLOCKSIZE)]
		s = 0

		sys.stdout.write("FINDING AVAILABLE CHANNEL ID: ");
		sys.stdout.flush()

		while s < len(segments):
			segment = segments[s]

			encoded_channel_id = narrowcast_encode_segment(narrowcast_current_id_hash(), cipher)


			# set if anything is set by anyone else.
			domain = encoded_channel_id + '.' + NARROWCAST_CONF['domain']
			try:
				answer = resolver.query(domain, 'TXT')
				if len(answer) > 0:
					print "INUSE: " + domain
					narrowcast_current_id_inc()
					continue
			except:
				pass

			# try to set it.
			encoded_segment = narrowcast_encode_segment(segment, cipher)
			domain = encoded_segment + '.' + encoded_channel_id + '.' + NARROWCAST_CONF['domain']

			try:
				answer = resolver.query(domain, 'A')
			except:
				continue;

			# saved
			if(answer[0].address == '0.0.0.0'):
				print "SET: " + domain
				print  "`--> '" + narrowcast_current_id() + "' = '" + segment + "'"
				s += 1
				narrowcast_current_id_inc()
			# in use.
			elif(answer[0].address == '255.255.255.255'):
				print "INUSE: " + domain + " (UNEXPECTED, SKIPPED)"
				domain = encoded_channel_id + '.' + NARROWCAST_CONF['domain']
				answer = resolver.query(domain, 'TXT')
				decoded = narrowcast_decode_segment(answer[0].to_text().strip('"'), cipher)
				narrowcast_current_id_inc() # skip it? probably shouldn't.
			else:
				print "UNEXPECTED '" + narrowcast_current_id() + "'"

		print "PUSH COMPLETE!"
		sys.exit(0)

	# listen mode.
	print "Listening..."
	print "-" * 80
	while True:
		encoded_channel_id = narrowcast_encode_segment(narrowcast_current_id_hash(), cipher)
		domain = encoded_channel_id + '.' + NARROWCAST_CONF['domain']

		try:
			answer = resolver.query(domain, 'TXT')
		except:
			time.sleep(2)
			continue;

		if len(answer) != 1:
			time.sleep(2)
			continue;

		decoded = narrowcast_decode_segment(answer[0].to_text().strip('"'), cipher)

		sys.stdout.write(decoded);
		sys.stdout.flush()

		narrowcast_current_id_inc()
