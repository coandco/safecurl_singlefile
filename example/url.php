<?php
/*
 * url.php
 *
 * Using SafeCurl\Url to only valid a URL
 */
require 'SafeCurl.php';

use SafeCurl\Options;
use SafeCurl\Url;

try {
    $safeUrl = Url::validateUrl('http://google.com', new Options());
} catch (Exception $e) {
    //Handle exception
}
