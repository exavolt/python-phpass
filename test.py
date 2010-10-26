#!/usr/bin/env python

import phpass

ok = 0

# Try to use stronger but system-specific hashes, with a possible fallback to
# the weaker portable hashes.
t_hasher = phpass.PasswordHash(8, False)

correct = 'test12345'
hx = t_hasher.hash_password(correct)

print 'Hash: %r' % hx

check = t_hasher.check_password(correct, hx)
if check:
    ok += 1
print "Check correct: %r (should be True)" % check

wrong = 'test12346'
check = t_hasher.check_password(wrong, hx)
if not check:
    ok += 1
print "Check wrong: %r (should be False)" % check

t_hasher = None

# Force the use of weaker portable hashes.
t_hasher = phpass.PasswordHash(8, True)

hx = t_hasher.hash_password(correct)

print 'Hash: %r' % hx

check = t_hasher.check_password(correct, hx)
if check:
    ok += 1
print "Check correct: %r (should be True)" % check

check = t_hasher.check_password(wrong, hx)
if not check:
    ok += 1
print "Check wrong: %r (should be False)" % check

# A correct portable hash for 'test12345'.
# Please note the use of single quotes to ensure that the dollar signs will
# be interpreted literally.  Of course, a real application making use of the
# framework won't store password hashes within a PHP source file anyway.
# We only do this for testing.
hx = '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'

print 'Hash: %r' % hx

check = t_hasher.check_password(correct, hx)
if check:
    ok += 1
print "Check correct: %r (should be True)" % check

check = t_hasher.check_password(wrong, hx)
if not check:
    ok += 1
print "Check wrong: %r (should be False)" % check

if ok == 6:
	print "All tests have PASSED"
else:
	print "Some tests have FAILED"

