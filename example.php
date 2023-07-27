<?php

$plaintext = 'Muhamad Zainal Arifin';
$secretKey = 'inirahasia';
$ivSecretKey = 'inilebihrahasia';
$method = 'aes-256-cbc';

$key = substr(hash('sha256', $secretKey, true), 0, 32);
$iv = substr(hash('sha256', $ivSecretKey, true), 0, 16);
// if use binary
// $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
$encrypted = base64_encode(openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv));
$decrypted = openssl_decrypt(base64_decode($encrypted), $method, $key, OPENSSL_RAW_DATA, $iv);

echo 'plaintext=' . $plaintext . "\n";
echo 'cipher=' . $method . "\n";
echo 'encrypted to: ' . $encrypted . "\n";
echo 'decrypted to: ' . $decrypted . "\n\n";
