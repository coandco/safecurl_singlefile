<?php
require 'SafeCurl.php''

use SafeCurl\SafeCurl;

try {
    $curlHandle = curl_init();
    $result = SafeCurl::execute('https://fin1te.net', $curlHandle);
} catch (Exception $e) {
    //Handle exception
}
