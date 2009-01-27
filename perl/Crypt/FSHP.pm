#!/usr/bin/env perl

package Crypt::FSHP;

use warnings;
use strict;

use Carp qw(croak);
use Digest;
use Digest::SHA;
use MIME::Base64 ();

use vars qw(@ISA @EXPORT $VERSION);

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(fshp_crypt fshp_check);
$VERSION = '1.00';

our $FSHP_META_FMTSTR = "{FSHP%d|%d|%d}%s";
our $FSHP_REGEX = qr /^\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)$/;
our %FSHP_VARIANT_ALGOMAP = (
	0 => 'SHA-1',
	1 => 'SHA-256',
	2 => 'SHA-384',
	3 => 'SHA-512'
);


sub fshp_crypt ($;$$$$) { &crypt; }
sub fshp_check ($$) { &check; }

sub crypt ($;$$$$)
{	
	my ($passwd, $salt, $saltlen, $rounds, $variant) = @_;

	# Populate with default values if undef.
	defined($saltlen)	|| ($saltlen = 8);
	defined($rounds)	|| ($rounds  = 4096);
	defined($variant)	|| ($variant = 1);

	unless (defined($salt)) {
		$salt = '';
		for (my $i = 0; $i < $saltlen ; $i++) {
			$salt .= chr(int(rand(256)));
		}
	} else {
		$saltlen = length($salt);
	}

	exists($FSHP_VARIANT_ALGOMAP{$variant}) ||
		croak("Unsupported FSHP variant '$variant'");

	my ($hash, $digest, $b64saltdigest);
	$hash = Digest->new($FSHP_VARIANT_ALGOMAP{$variant});
	$digest = $hash->add($salt . $passwd)->digest();
	for (my $i = 0; $i < $rounds - 1; $i++) {
		$digest = $hash->reset()->add($digest)->digest();
	}

	$b64saltdigest = MIME::Base64::encode($salt . $digest, "");

	return sprintf($FSHP_META_FMTSTR,
			$variant, $saltlen, $rounds, $b64saltdigest);
}

sub check ($$)
{
	my ($passwd, $ciphertext) = @_;

	$ciphertext =~ $FSHP_REGEX || (return 0);

	my ($variant, $saltlen, $rounds, $b64saltdigest) = ($1, $2, $3, $4);
	my $salt = substr(MIME::Base64::decode($b64saltdigest), 0, $saltlen);

	return &crypt($passwd, $salt, 0, $rounds, $variant) eq $ciphertext;
}

1;
__END__

=head1 NAME

FSHP - Fairly Secure Hashed Passwords. A PKCS#5 PBKDF1 similar implementation.

=head1 SYNOPSIS

  use Crypt::FSHP;

  $hashed_pw = fshp_crypt("OrpheanBeholderScryDoubt");
  print "OK\n" if fshp_check("OrpheanBeholderScryDoubt", $hashed_pw);

=head1 DESCRIPTION

Fairly Secure Hashed Password (FSHP) is a salted, iteratively hashed
password hashing implementation.

Design principle is similar with PBKDF1 specification in RFC 2898
(PKCS #5: Password-Based Cryptography Specification Version 2.0)
FSHP allows choosing the salt length, number of iterations and the
underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).

=head2 FUNCTIONS

=over 4

=item crypt($passwd, $salt, $saltlen, $rounds, $variant)

=item check($passwd, $ciphertext)

=back

If you prefer not to import these routines into your namespace, you can
call them as:

    use Crypt::FSHP ();
    $hashed_pw = Crypt::FSHP::crypt($passwd);
    print "OK\n" if Crypt::FSHP::check($passwd, $hashed_pw);

=head2 SECURITY

Default variant FSHP1 employs 8 byte salts and makes 4096 iterations of
SHA-256 hashing.

=over 4

=item * 8 byte salt renders rainbow table attacks impractical by multiplying
the required space with 2^64.

=item * 4096 iterations causes brute force attacks to be fairly expensive.

=item * There are no known attacks against SHA-256 to find collisions with
    a computational effort of fewer than 2^128 operations at the time of
    this release.

=back

=head1 AUTHOR

Berk D. Demir <bdd@mindcast.org>

=head1 COPYRIGHT

Copyright (c) 2009 Berk D. Demir

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

=cut