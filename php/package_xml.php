<?php
require_once 'PEAR/PackageFileManager2.php';
PEAR::setErrorHandling(PEAR_ERROR_DIE);

$packagexml = new PEAR_PackageFileManager2;

$options = array(
    'filelistgenerator' => 'file',
    'changelogoldtonew' => false,
    'simpleoutput'      => false,
    'baseinstalldir'    => 'Crypt',
    'packagedirectory'  => dirname(__FILE__),
    'clearcontents'     => true,
    'ignore'            => array('package_xml.php'),
    'dir_roles'         => array('test' => 'test')
);
$packagexml->setOptions($options);

$packagexml->setPackageType('php');
$packagexml->setPackage('Crypt_FSHP');
$packagexml->setSummary('Fairly Secure Hashed Passwords.' .
                        ' A PBKDF1 similar implementation.');

$package_description = <<<EOD
Fairly Secure Hashed Password (FSHP) is a salted, iteratively hashed password
hashing implementation.

Design principle is similar with PBKDF1 specification in RFC 2898
(a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0)

FSHP allows choosing the salt length, number of iterations and the underlying
cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).
EOD;
$packagexml->setDescription($package_description);

$packagexml->setChannel('pear.php.net');

$notes = <<<EON
* Initial release.
EON;
$packagexml->setNotes($notes);

$packagexml->setPhpDep('5.1.2');
$packagexml->setPearinstallerDep('1.4.0b1');
$packagexml->addPackageDepWithChannel('required',
    'PEAR', 'pear.php.net', '1.3.3');

$packagexml->addMaintainer('lead', 'bdd', 'Berk D. Demir', 'bdd@mindcast.org');
$packagexml->setLicense('Public Domain',
                        'http://creativecommons.org/licenses/publicdomain/');

$packagexml->addRelease();
$packagexml->generateContents();

$packagexml->setAPIVersion('1.0');
$packagexml->setReleaseVersion('1.0.0');
$packagexml->setReleaseStability('stable');
$packagexml->setAPIStability('stable');
$packagexml->addGlobalReplacement('package-info', '@release_version@', 'version');

if (isset($_GET['make']) ||
    (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')) {
    $packagexml->writePackageFile();
} else {
    $packagexml->debugPackageFile();
}

?>