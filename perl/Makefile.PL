use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => 'Crypt::FSHP',
	ABSTRACT => 'Fairly Secure Hashed Password (PBKDF1 implementation from RFC 2898/PKCS#5)',
	AUTHOR => 'Berk D. Demir <bdd@mindcast.org>',
	VERSION_FROM  => 'lib/Crypt/FSHP.pm',
	PREREQ_PM => {
		'Carp' => '0',
		'Digest' => '0',
		'Digest::SHA' => '0',
		'MIME::Base64' => '0'
	}
);
