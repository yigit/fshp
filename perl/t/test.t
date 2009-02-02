use strict;
use lib '../lib';

use Test::Simple tests => 9;
use Crypt::FSHP;

## Basic Test:
# - Tests the basic functionality and full parameter function calling.
# - Tests the existence of digest algorithms with enumerating variants.
# COMMON: passwd='test', salt='1234', rounds=4
my %variant_test_vectors = (
	0 => '{FSHP0|4|4}MTIzNLyZ2V9fBN2+GqXG/HSO5yLvAeYn',
	1 => '{FSHP1|4|4}MTIzNOxb/zCbpTUpBzg3cA3OhGJ+5lrOSem5b8u9jNc4mL6n',
	2 => '{FSHP2|4|4}MTIzNILcBiPXCD61HeZxdgGJOBXAOdE/5uQ8u0vs6T1OmdPFWQlfkleElEgwMtiKhFY9CA==',
	3 => '{FSHP3|4|4}MTIzNMEhvfLnVLhUSZIO+a7bEXcr10gtthwgMeyFx5qd+W2yyftnH1T1J1srwELvCbg871F8FMKm5c75Moy7BrTMdpw='
);

for (my $i = 0; $i <= length(%variant_test_vectors); $i++) {
	ok (
		Crypt::FSHP::crypt('test', '1234', 0, 4, $i) eq $variant_test_vectors{$i},
		"crypt() with FSHP variant $i works."
	);
}

ok (
	Crypt::FSHP::check('test', $variant_test_vectors{0}),
	"check() works."
);

ok (
	fshp_crypt('test', '1234', 0, 4, 1) eq $variant_test_vectors{1},
	"fshp_crypt() exported as global and works."
);

ok (
	fshp_check('test', $variant_test_vectors{1}),
	"fshp_check() exported as global and works."
);

ok (
	Crypt::FSHP::crypt('test') =~ /^\{FSHP1\|8\|4096\}[\d\w\+\/=]{56}$/,
	'single parameter crypt() outputs proper FSHP1 default.'
);

ok (
	Crypt::FSHP::crypt('test', undef, -1, -1, 0) =~ /^\{FSHP0\|0\|1\}[\d\w\+\/=]{28}$/,
	'acts sane with unsane parameters (rounds < 0, saltlen < 0)'
);