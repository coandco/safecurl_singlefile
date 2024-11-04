<?php
/*
 * options.php
 *
 * Using SafeCurl with custom options
 */
require 'SafeCurl.php';

use SafeCurl\SafeCurl;
use SafeCurl\Options;

try {
    $curlHandle = curl_init();

    $options = new Options();
    //Completely clear the whitelist
    $options->setList('whitelist', []);
    //Completely clear the blacklist
    $options->setList('blacklist', []);
    //Set the domain whitelist only
    $options->setList('whitelist', ['google.com', 'youtube.com'], 'domain');

    $result = SafeCurl::execute('http://www.youtube.com', $curlHandle);
} catch (Exception $e) {
    //Handle exception
}
