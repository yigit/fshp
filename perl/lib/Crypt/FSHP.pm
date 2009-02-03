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
$VERSION = '0.2.3';

our $FSHP_META_FMTSTR = "{FSHP%d|%d|%d}%s";
our $FSHP_REGEX = qr/^\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)$/;
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

	# Passwd undefined? Not using strict or just trying to abuse.
	defined($passwd) || croak('Mandatory argument $passwd can not be undefined');
    
	# Populate with default values if undef.
	defined($saltlen)	|| ($saltlen = 8);
	defined($rounds)	|| ($rounds  = 4096);
	defined($variant)	|| ($variant = 1);
	
	# Ensure we have sane values for salt length and rounds.
	$saltlen	= 0 if ($saltlen < 0);
	$rounds		= 1 if ($rounds < 1);

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
	for (my $i = 1; $i < $rounds; $i++) {
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

  $passwd_hash = fshp_crypt($passwd_clear);
  if (fshp_check($passwd_clear, $passwd_hash)) {
      let_user_in();
  }

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
    
    $passwd_hash = Crypt::FSHP::crypt($passwd_clear);
    if (Crypt::FSHP::check($passwd_clear, $passwd_hash)) {
        let_user_in();
    }

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

Authors of this computer software disclaim their respective copyright
on the source code and related documentation, thus releasing their work
to Public Domain.

In case you are forced by your lawyer to get a copyright license,
you may contact any of the authors to get this software (and its related
documentation) with a BSD type license.

=cut