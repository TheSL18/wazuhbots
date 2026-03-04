<?php
// DVWA Configuration for WazuhBOTS
// Intentionally vulnerable - DO NOT use in production

$_DVWA = array();
$_DVWA['db_server']   = '127.0.0.1';
$_DVWA['db_database'] = 'dvwa';
$_DVWA['db_user']     = 'dvwa';
$_DVWA['db_password'] = 'p@ssw0rd';
$_DVWA['db_port']     = '3306';

// Security level: low (intentionally vulnerable for CTF)
$_DVWA['default_security_level'] = 'low';

$_DVWA['recaptcha_public_key']  = '';
$_DVWA['recaptcha_private_key'] = '';

$_DVWA['default_locale'] = 'en';
