#!/usr/bin/env python

# Goal: Password cracker that can read a shadow file
# or just a hash, auto-detect the type of hash, and
# perform a dictionary attack on said hash.

import sys
import crypt
import optparse


VERBOSE = False
DISPLAY_PROGRESS = False

# Prints string s if -v flag is set.
def v_print(s):
    if VERBOSE == True:
        print s


# Takes the name of a shadow file as input.
# Returns a list of unique hashes found in that file.
def extract_hashes(shadow_filename):
    f = open(shadow_filename, 'r')
    lines = f.readlines()
    f.close()

    # Store the password fields in a set since duplicates can be ignored.
    hashes = set()
    for line in lines:    
        hashes.add(line.split(":")[1].strip()) # Added replace to cut leading/ending spaces from the hash (there were some in the violent python example).
    
    # Keep only valid hashes
    valid_hashes = []
    for h in hashes:
        if len(h) != 1:
            valid_hashes.append(h)
    
    return valid_hashes


# Extracts all the usernames from a shadow file so the usernames can be
# added to the list of potential passwords.
def extract_usernames(shadow_filename):
    f = open(shadow_filename, 'r')
    lines = f.readlines()    
    f.close()
    
    users = []
    for line in lines:
        users.append(line.split(":")[0])
        
    return users


# Returns the type of hash in string h.
# If the hash type is unknown, returns False.
def get_hash_type(h):
    if len(h) == len("12zDFvFETEoAQ"):
        return "des"
    elif h[1] == "1" and len(h) == len("$1$12312323$nXoTg6iyhbJEqMRLg06XA."):
        return "md5"
    elif h[1] == "5" and len(h) == len("$5$12312323$7GlgJsUb1sJFF4zzm81ssaDLc0PTg5xZTU3mIAnJSW/"):
        return "sha-256"
    elif h[1] == "6" and len(h) == len("$6$12312323$U01k21VwW0Bdrfd412VYv5Q08G0SJcAXhE7EBF4.6eViexdF1t39N446qQvHTjep6jT7/a.ZExOWCdj4DoajF/"):
        return "sha-512"
    else:
        return False
        

# Returns the salt included in the given hash string.
def extract_salt(h):
    # If there is a $ in the hash, assume it is MD5/SHA.
    if "$" in h:
        return h.split("$")[2]
    # Otherwise, assume it is DES.
    else:
        return h[0:2]


# Checks if any words in the dictionary match a given hash and salt.
def test_dictionary(h, salt):
    print "    >>> Testing hash against dictionary..."
    
    word_count = 0
    for word in dictionary:

        if h == crypt.crypt(word.rstrip(), salt):  # rstrip removes trailing whitespace at the end of the line caused by f.readlines().
            print "[+] The password is: %s" % word
            return word

        word_count += 1
        if word_count % 100000 == 0 and DISPLAY_PROGRESS != 0:
            percent_complete = float(word_count) / dictionary_length * 100.0
            print "        %.2f%% complete on this hash (%d/%d)" % ( percent_complete,
                  word_count, dictionary_length)

    # Return False if the password is not found.
    print "[-] The dictionary did not contain this password.\n"
    return False
    
    
# Cracks a individual hash in string h.
# Outputs hashes/passwords to screen.
# Returns True or False depending on whether or not a hash is
# successfully cracked.
def crack_hash(h):
    v_print("")

    hash_type = get_hash_type(h)
    if not hash_type:
        print "[!] Unidentifiable hash: %s" % h
        return False
    elif hash_type == "des":
        print "[+] Identified 56-bit DES hash: %s" % h
    elif hash_type == "md5":
        print "[+] Identified MD5 hash: %s" % h
    elif hash_type == "sha-256":
        print "[+] Identified SHA-256 hash: %s" % h
    elif hash_type == "sha-512":
        print "[+] Identified SHA-512 hash: %s" % h 

    # Determine the salt used to create the hash.
    salt = extract_salt(h)
    v_print("    Salt: %s" % salt)

    # Add the hash-type to the salt for use with crypt
    if h[0] == "$":
        salt = h[0:3] + salt

    # Test words from the dictionary against the hash.
    valid_password = test_dictionary(h, salt)
    return valid_password


def main():

    # This first section just handles command-line options
    version = "2.0"
    description = "Password Cracker v%s" % version
    
    parser = optparse.OptionParser(description=description, version=version)
    parser.add_option("-s", dest="shadowfile", type="string", 
                      help="shadow file containing hashes to crack.")
    parser.add_option("-H", dest="userhash", type="string", 
                      help="Single hash to be cracked. Overrides -s.")
    parser.add_option("-d", dest="dictionary", type="string", 
                      help="Dictionary file containing passwords to check against hashes.")
    parser.add_option("-o", dest="outfile", type="string", help="Output file where valid logins will be stored.")
    parser.add_option("-v", dest="verbose", action="store_true",
                      help="Verbose output.", default=False)
    parser.add_option("-p", dest="progress", action="store_true", default=False,
                      help="Display progress of each hash as it is cracked.")
    
    if len(sys.argv) == 1: parser.print_help(); sys.exit();
    
    (options, args) = parser.parse_args()
    shadow_filename = options.shadowfile
    user_hash = options.userhash
    dictionary_filename = options.dictionary
    output_file = options.outfile
    global VERBOSE; VERBOSE = options.verbose
    global DISPLAY_PROGRESS; DISPLAY_PROGRESS = options.progress
    
    # The actual program begins...
    
    # Print the program name, version, etc.
    print "=" * 80
    print " " + description
    print "=" * 80

    # Read the hashes from either user-input or a shadow file.
    if user_hash == None:
        hashes = extract_hashes(shadow_filename)
    else:
        hashes = [user_hash]
    print "[+] %d hashes loaded." % len(hashes)

    
    # Load the password dictionary into memory.
    # I moved this here so the dictionary would only need to get loaded into
    # memory once.
    #if dictionary_filename == None:
    #    print "[-] ERROR: You must supply a dictionary file."
    #    sys.exit()
        
    global dictionary
    global dictionary_length
    
    if dictionary_filename != None:
        print "[+] Reading dictionary: %s..." % dictionary_filename
    
        f = open(dictionary_filename, 'r')
        dictionary = f.readlines()    
        f.close()
        
        dictionary_length = len(dictionary)
        print "[+] Loaded %d words from the dictionary." % (dictionary_length)
    else:
        dictionary = []
        
    
    # Add usernames from the shadow file to the top of the dictionary.
    if shadow_filename != None:
        usernames = extract_usernames(shadow_filename)
        print "[+] Will try %d usernames from the shadow file as possible passwords." % len(usernames)
        dictionary = usernames + dictionary
        dictionary_length = len(dictionary)

   
    # Crack each hash in the hashes list.
    for h in hashes:
        valid_password = crack_hash(h)
        if valid_password != False and output_file != None:
            outfile = open(output_file, 'a')
            outfile.write("%s:%s\n" % (h, valid_password))
            outfile.close()
            

if __name__ == "__main__":
    main()