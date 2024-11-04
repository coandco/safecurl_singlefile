<?php
namespace SafeCurl;
class Exception extends \Exception { }


namespace SafeCurl\Exception;
use SafeCurl\Exception;
class InvalidURLException extends Exception { }
class InvalidOptionException extends Exception { }


namespace SafeCurl\Exception\InvalidURLException;
use SafeCurl\Exception\InvalidURLException;
class InvalidDomainException extends InvalidURLException { }
class InvalidIPException extends InvalidURLException { }
class InvalidPortException extends InvalidURLException { }
class InvalidSchemeException extends InvalidURLException { }


namespace SafeCurl;
class IpAddress {

	const TYPE_IPV4 = 4;
	const TYPE_IPV6 = 6;

	private $address;
	private $type;

	public function __construct(string $address, int $type = self::TYPE_IPV4) {
		$this->address = $address;
		$this->type = $type;
	}

	public function getAddress() : string {
		return $this->address;
	}

	public function getType() : int {
		return $this->type;
	}

	public function __toString() : string {
		return $this->address;
	}

}

use SafeCurl\Exception\InvalidOptionException;
class Options {

	const IP_LISTS = [
		IpAddress::TYPE_IPV4 => 'ip',
		IpAddress::TYPE_IPV6 => 'ipv6'
	];

	const DEFAULT_IP_BLACKLIST = [
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/29',
		'192.0.2.0/24',
		'192.88.99.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4'
	];
	const DEFAULT_IPV6_BLACKLIST = [
		'::1/128',
		'::/128',
		'::ffff:0:0/96',
		'64:ff9b::/96',
		'64:ff9b:1::/48',
		'100::/64',
		'2001::/23',
		'2001::/32',
		'2001:1::1/128',
		'2001:1::2/128',
		'2001:1::3/128',
		'2001:2::/48',
		'2001:3::/32',
		'2001:4:112::/48',
		'2001:10::/28',
		'2001:20::/28',
		'2001:30::/28',
		'2001:db8::/32',
		'2002::/16',
		'2620:4f:8000::/48',
		'5f00::/16',
		'fc00::/7',
		'fe80::/10'
	];

	/**
	 * @var bool Follow HTTP redirects
	 */
	private $followLocation = false;

	/**
	 * @var int Redirect limit. 0 is infinite
	 */
	private $followLocationLimit = 0;

	/**
	 * @var bool Allow credentials in a URL
	 */
	private $sendCredentials = false;

	/**
	 * @var bool Pin DNS records
	 */
	private $pinDns = false;

	/**
	 * @var array
	 */
	private $whitelist = array('ip'     => array(),
		'ipv6'   => array(),
		'port'   => array('80', '443', '8080'),
		'domain' => array(),
		'scheme' => array('http', 'https'));

	/**
	 * @var array
	 */
	private $blacklist = array('ip'     => self::DEFAULT_IP_BLACKLIST,
		'ipv6'	=> self::DEFAULT_IPV6_BLACKLIST,
		'port'   => array(),
		'domain' => array(),
		'scheme' => array());

	private $headers = null;

	/**
	 * @return SafeCurl\Options
	 */
	public function __construct() { }

	/**
	 * Get followLocation
	 *
	 * @return bool
	 */
	public function getFollowLocation() {
		return $this->followLocation;
	}

	/**
	 * Enables following redirects
	 *
	 * @return SafeCurl\Options
	 */
	public function enableFollowLocation() {
		$this->followLocation = true;

		return $this;
	}

	/**
	 * Disables following redirects
	 *
	 * @return SafeCurl\Options
	 */
	public function disableFollowLocation() {
		$this->followLocation = false;

		return $this;
	}

	/**
	 * Gets the follow location limit
	 * 0 is no limit (infinite)
	 *
	 * @return int
	 */
	public function getFollowLocationLimit() {
		return $this->followLocationLimit;
	}

	/**
	 * Sets the follow location limit
	 * 0 is no limit (infinite)
	 *
	 * @param $limit int
	 *
	 * @return SafeCurl\Options
	 */
	public function setFollowLocationLimit($limit) {
		if (!is_numeric($limit) || $limit < 0) {
			throw new InvalidOptionException("Provided limit '$limit' must be an integer >= 0");
		}

		$this->followLocationLimit = $limit;

		return $this;
	}

	/**
	 * Get send credentials option
	 *
	 * @return bool
	 */
	public function getSendCredentials() {
		return $this->sendCredentials;
	}

	/**
	 * Enable sending of credenitals
	 *
	 * @return SafeCurl\Options
	 */
	public function enableSendCredentials() {
		$this->sendCredentials = true;

		return $this;
	}

	/**
	 * Disable sending of credentials
	 *
	 * @return SafeCurl\Options
	 */
	public function disableSendCredentials() {
		$this->sendCredentials = false;

		return $this;
	}

	/**
	 * Get pin DNS option
	 *
	 * @return bool
	 */
	public function getPinDns() {
		return $this->pinDns;
	}

	/**
	 * Enable DNS pinning
	 *
	 * @return SafeCurl\Options
	 */
	public function enablePinDns() {
		$this->pinDns = true;

		return $this;
	}

	/**
	 * Disable DNS pinning
	 *
	 * @return SafeCurl\Options
	 */
	public function disablePinDns() {
		$this->pinDns = false;

		return $this;
	}

	/**
	 * Checks if a specific value is in a list
	 *
	 * @param $list   string
	 * @param $type   string
	 * @param $values string
	 *
	 * @return bool
	 */
	public function isInList($list, $type, $value) {
		if (!in_array($list, array('whitelist', 'blacklist'))) {
			throw new InvalidOptionException("Provided list '$list' must be 'whitelist' or 'blacklist'");
		}

		if (!array_key_exists($type, $this->$list)) {
			throw new InvalidOptionException("Provided type '$type' must be 'ip', 'port', 'domain' or 'scheme'");
		}

		if (empty($this->{$list}[$type])) {
			if ($list == 'whitelist') {
				//Whitelist will return true
				return true;
			}
			//Blacklist returns false
			return false;
		}

		//For domains, a regex match is needed
		if ($type == 'domain') {
			foreach ($this->{$list}[$type] as $domain) {
				if (preg_match('/^' . $domain . '$/i', $value)) {
					return true;
				}
			}

			return false;
		} else {
			return (in_array($value, $this->{$list}[$type]));
		}
	}

	/**
	 * Returns a specific list
	 *
	 * @param $list string
	 * @param $type string optional
	 *
	 * @return array
	 */
	public function getList($list, $type = null) {
		if (!in_array($list, array('whitelist', 'blacklist'))) {
			throw new InvalidOptionException("Provided list '$list' must be 'whitelist' or 'blacklist'");
		}

		if ($type !== null) {
			if (!array_key_exists($type, $this->$list)) {
				throw new InvalidOptionException("Provided type '$type' must be 'ip', 'port', 'domain' or 'scheme'");
			}

			return $this->{$list}[$type];
		}

		return $this->{$list};
	}

	/**
	 * Sets a list to the passed in array
	 *
	 * @param $list   string
	 * @param $values array
	 * @param $type   string optional
	 *
	 * @return SafeCurl\Options
	 */
	public function setList($list, $values, $type = null) {
		if (!in_array($list, array('whitelist', 'blacklist'))) {
			throw new InvalidOptionException("Provided list '$list' must be 'whitelist' or 'blacklist'");
		}

		if (!is_array($values)) {
			throw new InvalidOptionException("Provided values must be an array");
		}

		if ($type !== null) {
			if (!array_key_exists($type, $this->$list)) {
				throw new InvalidOptionException("Provided type '$type' must be 'ip', 'port', 'domain' or 'scheme'");
			}

			$this->{$list}[$type] = $values;

			return $this;
		}

		foreach ($values as $type => $value) {
			if (!in_array($type, array('ip', 'port', 'domain', 'scheme'))) {
				throw new InvalidOptionException("Provided type '$type' must be 'ip', 'port', 'domain' or 'scheme'");
			}

			$this->{$list}[$type] = $value;
		}

		return $this;
	}

	/**
	 * Adds a value/values to a specific list
	 *
	 * @param $list   string
	 * @param $type   string
	 * @param $values array|string
	 *
	 * @return SafeCurl\Options
	 */
	public function addToList($list, $type, $values) {
		if (!in_array($list, array('whitelist', 'blacklist'))) {
			throw new InvalidOptionException("Provided list '$list' must be 'whitelist' or 'blacklist'");
		}

		if (!array_key_exists($type, $this->$list)) {
			throw new InvalidOptionException("Provided type '$type' must be 'ip', 'port', 'domain' or 'scheme'");
		}

		if (empty($values)) {
			throw new InvalidOptionException("Provided values cannot be empty");
		}

		//Cast single values to an array
		if (!is_array($values)) {
			$values = array($values);
		}

		foreach ($values as $value) {
			if (!in_array($value, $this->{$list}[$type])) {
				$this->{$list}[$type][] = $value;
			}
		}

		return $this;
	}

	/**
	 * Removes a value/values from a specific list
	 *
	 * @param $list   string
	 * @param $type   string
	 * @param $values array|string
	 *
	 * @return SafeCurl\Options
	 */
	public function removeFromList($list, $type, $values) {
		if (!in_array($list, array('whitelist', 'blacklist'))) {
			throw new InvalidOptionException("Provided list '$list' must be 'whitelist' or 'blacklist'");
		}

		if (!array_key_exists($type, $this->$list)) {
			throw new InvalidOptionException("Provided type '$type' must be 'ip', 'port', 'domain' or 'scheme'");
		}

		if (empty($values)) {
			throw new InvalidOptionException("Provided values cannot be empty");
		}

		//Cast single values to an array
		if (!is_array($values)) {
			$values = array($values);
		}

		$this->{$list}[$type] = array_diff($this->{$list}[$type], $values);

		return $this;
	}

	public function setHeaders(?array $headers) {
		$this->headers = $headers;
	}

	public function getHeaders() {
		return $this->headers;
	}
}

use SafeCurl\Exception\InvalidURLException;
use SafeCurl\Exception\InvalidURLException\InvalidDomainException;
use SafeCurl\Exception\InvalidURLException\InvalidIPException;
use SafeCurl\Exception\InvalidURLException\InvalidPortException;
use SafeCurl\Exception\InvalidURLException\InvalidSchemeException;
use Throwable;

class Url {
	/**
	 * Validates the whole URL
	 *
	 * @param $url     string
	 * @param $options SafeCurl\Options
	 *
	 * @return string
	 */
	public static function validateUrl($url, Options $options) {
		if (trim($url) == '') {
			throw new InvalidURLException("Provided URL '$url' cannot be empty");
		}

		//Split URL into parts first
		$parts = parse_url($url);

		if (empty($parts)) {
			throw new InvalidURLException("Error parsing URL '$url'");
		}

		if (!array_key_exists('host', $parts)) {
			throw new InvalidURLException("Provided URL '$url' doesn't contain a hostname");
		}

		//First, validate the scheme
		if (array_key_exists('scheme', $parts)) {
			$parts['scheme'] = self::validateScheme($parts['scheme'], $options);
		} else {
			//Default to http
			$parts['scheme'] = 'http';
		}

		//Validate the port
		if (array_key_exists('port', $parts)) {
			$parts['port'] = self::validatePort($parts['port'], $options);
		}

		//Reolve host to ip(s)
		$ips = self::resolveHostname($parts['host']);
		$parts['ips'] = $ips;

		//Validate the host
		$host = self::validateHostname($parts['host'], $ips, $options);
		$parts['host'] = $host;

		//Rebuild the URL
		$cleanUrl = self::buildUrl($parts);

		return array('originalUrl' => $url, 'cleanUrl' => $cleanUrl, 'parts' => $parts, 'host' => $host, 'ips' => $ips);
	}

	/**
	 * Validates a URL scheme
	 *
	 * @param $scheme  string
	 * @param $options SafeCurl\Options
	 *
	 * @return string
	 */
	public static function validateScheme($scheme, Options $options) {
		//Whitelist always takes precedence over a blacklist
		if (!$options->isInList('whitelist', 'scheme', $scheme)) {
			throw new InvalidSchemeException("Provided scheme '$scheme' doesn't match whitelisted values: "
				. implode(', ', $options->getList('whitelist', 'scheme')));
		}

		if ($options->isInList('blacklist', 'scheme', $scheme)) {
			throw new InvalidSchemeException("Provided scheme '$scheme' matches a blacklisted value");
		}

		//Existing value is fine
		return $scheme;
	}

	/**
	 * Validates a port
	 *
	 * @param $port    int
	 * @param $options SafeCurl\Options
	 *
	 * @return int
	 */
	public static function validatePort($port, Options $options) {
		if (!$options->isInList('whitelist', 'port', $port)) {
			throw new InvalidPortException("Provided port '$port' doesn't match whitelisted values: "
				. implode(', ', $options->getList('whitelist', 'port')));
		}

		if ($options->isInList('blacklist', 'port', $port)) {
			throw new InvalidPortException("Provided port '$port' matches a blacklisted value");
		}

		//Existing value is fine
		return $port;
	}

	/**
	 * Validates a URL hostname
	 *
	 * @param $hostname string
	 * @param $options  SafeCurl\Options
	 *
	 * @returns string
	 */
	public static function validateHostname($hostname, $ips, Options $options) {
		//Check the host against the domain lists
		if (!$options->isInList('whitelist', 'domain', $hostname)) {
			throw new InvalidDomainException("Provided hostname '$hostname' doesn't match whitelisted values: "
				. implode(', ', $options->getList('whitelist', 'domain')));
		}

		if ($options->isInList('blacklist', 'domain', $hostname)) {
			throw new InvalidDomainException("Provided hostname '$hostname' matches a blacklisted value");
		}

		foreach (Options::IP_LISTS as $ipType => $listName) {
			$cidrMatch = self::getCidrMatchFunction($ipType);

			$whitelistedIps = $options->getList('whitelist', $listName);

			if (!empty($whitelistedIps)) {
				$valid = false;

				foreach ($whitelistedIps as $whitelistedIp) {
					foreach ($ips as $ip) {
						if ($ip->getType() != $ipType)
							continue;
						if ($cidrMatch($ip, $whitelistedIp)) {
							$valid = true;
							break 2;
						}
					}
				}

				if (!$valid) {
					throw new InvalidIpException("Provided hostname '$hostname' resolves to '" . implode(', ', $ips)
						. "', which doesn't match whitelisted values: "
						. implode(', ', $whitelistedIps));
				}
			}

			$blacklistedIps = $options->getList('blacklist', $listName);

			if (!empty($blacklistedIps)) {
				foreach ($blacklistedIps as $blacklistedIp) {
					foreach ($ips as $ip) {
						if ($ip->getType() != $ipType)
							continue;
						if ($cidrMatch($ip, $blacklistedIp)) {
							throw new InvalidIpException("Provided hostname '$hostname' resolves to '" . implode(', ', $ips)
								. "', {$ip} matches a blacklisted value: " . $blacklistedIp);
						}
					}
				}
			}
		}

		return $hostname;
	}

	/**
	 * Re-build a URL based on an array of parts
	 *
	 * @param $parts array
	 *
	 * @return string
	 */
	public static function buildUrl($parts) {
		$url  = '';

		$url .= (!empty($parts['scheme']))
			? $parts['scheme'] . '://'
			: '';

		$url .= (!empty($parts['user']))
			? rawurlencode($parts['user'])
			: '';

		$url .= (!empty($parts['pass']))
			? ':' . rawurlencode($parts['pass'])
			: '';

		//If we have a user or pass, make sure to add an "@"
		$url .= (!empty($parts['user']) || !empty($parts['pass']))
			? '@'
			: '';

		$url .= (!empty($parts['host']))
			? $parts['host']
			: '';

		$url .= (!empty($parts['port']))
			? ':' . (int) $parts['port']
			: '';

		$url .= (!empty($parts['path']))
			? str_replace('%2F', '/', rawurlencode($parts['path']))
			: '';

		//The query string is difficult to encode properly
		//We need to ensure no special characters can be
		//used to mangle the URL, but URL encoding all of it
		//prevents the query string from being parsed properly
		if (!empty($parts['query'])) {
			$query = rawurlencode($parts['query']);
			//Replace encoded &, =, ;, [ and ] to originals
			$query = str_replace(array('%26', '%3D', '%3B', '%5B', '%5D'),
				array('&',   '=',   ';',   '[',   ']'),
				$query);

			$url .= '?' . $query;
		}

		$url .= (!empty($parts['fragment']))
			? '#' . rawurlencode($parts['fragment'])
			: '';

		return $url;
	}

	private static function getIps(string $hostname, int $recordType, string $ipField, int $ipType, array &$ips) : void {
		try {
			$records = dns_get_record($hostname, $recordType);
			if ($records !== false) {
				foreach ($records as $record) {
					$ip = $record[$ipField] ?? null;
					if ($ip !== null && strpos($ip, ',') === false)
						$ips[] = new IpAddress($ip, $ipType);
				}
			}
		}
		catch (Throwable $t) {
			// In some environments, dns_get_record may trigger an exception instead of returning false
		}
	}

	/**
	 * Resolves a hostname to its IP(s)
	 *
	 * @param $hostname string
	 *
	 * @return array
	 */
	public static function resolveHostname($hostname) {
		$ips = [];
		self::getIps($hostname, DNS_A, 'ip', IpAddress::TYPE_IPV4, $ips);
		self::getIps($hostname, DNS_AAAA, 'ipv6', IpAddress::TYPE_IPV6, $ips);
		if (empty($ips))
			throw new InvalidDomainException("Provided hostname '{$hostname}' could not be resolved to an IP address");
		return $ips;
	}

	/**
	 * Checks a passed in IP against a CIDR.
	 * See http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
	 *
	 * @param $ip   string
	 * @param $cidr string
	 *
	 * @return bool
	 */
	public static function cidrMatch(IpAddress $ip, $cidr) {
		if (strpos($cidr, '/') === false) {
			//It doesn't have a prefix, just a straight IP match
			return $ip == $cidr;
		}

		list($subnet, $mask) = explode('/', $cidr);
		if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet)) {
			return true;
		}

		return false;
	}

	public static function cidrMatchIpv6(IpAddress $ip, $cidr) {
		list($prefix, $mask) = explode('/', $cidr, 2);
		$prefixBinary = inet_pton($prefix);
		if ($prefixBinary === false)
			throw new Exception("Invalid IPv6 CIDR prefix: {$prefix}");
		$ipBinary = inet_pton($ip);
		if ($ipBinary === false)
			throw new InvalidIPException("Invalid IPv6 Address: {$ip}");
		if (!ctype_digit($mask))
			throw new Exception("Invalid IPv6 CIDR mask: {$mask}");
		$mask = (int) $mask;
		$length = strlen($prefixBinary);
		if ($length !== strlen($ipBinary))
			throw new Exception("CIDR prefix does not match address length: {$prefix}, IP: {$ip}");
		$bits = $length * 8;
		if ($mask > $bits)
			throw new Exception("CIDR mask exceeds address length({$bits}): {$mask}, IP: {$ip}, CIDR: {$cidr}");
		$remaining = $mask;
		for ($i = 0; $i < $length; $i++) {
			$a = ord($prefixBinary[$i]);
			$b = ord($ipBinary[$i]);
			if ($mask <= 0) {
				return true;
			}
			else if ($bits >= 8) {
				if ($a != $b)
					return false;
				$bits -= 8;
			}
			else {
				$shift = 8 - $bits;
				return ($a >> $shift) == ($b >> $shift);
			}
		}
		throw new Exception("Zero length IP or CIDR specified, IP: {$ip}, CIDR: {$cidr}");
	}

	public static function getCidrMatchFunction(int $ipType) {
		switch($ipType) {
			case IpAddress::TYPE_IPV6:
				return [self::class, 'cidrMatchIpv6'];
			case IpAddress::TYPE_IPV4:
			default:
				return [self::class, 'cidrMatch'];
		}
	}
}

use CurlHandle;

class SafeCurl {
	/**
	 * cURL Handle
	 *
	 * @var resource|CurlHandle
	 */
	private $curlHandle;

	/**
	 * SafeCurl Options
	 *
	 * @var SafeCurl\Options
	 */
	private $options;

	/**
	 * Returns new instance of SafeCurl\SafeCurl
	 *
	 * @param $curlHandle resource         A valid cURL handle
	 * @param $options    SafeCurl\Options optional
	 */
	public function __construct($curlHandle, Options $options = null) {
		$this->setCurlHandle($curlHandle);

		if ($options === null) {
			$options = new Options();
		}
		$this->setOptions($options);
		$this->init();
	}

	/**
	 * Returns cURL handle
	 *
	 * @return resource
	 */
	public function getCurlHandle() {
		return $this->curlHandle;
	}

	/**
	 * Sets cURL handle
	 *
	 * @param $curlHandle resource
	 */
	public function setCurlHandle($curlHandle) {
		if (!((is_resource($curlHandle) && get_resource_type($curlHandle) === 'curl') || (class_exists('CurlHandle') && $curlHandle instanceof CurlHandle))) {
			throw new Exception("SafeCurl expects a valid cURL resource - '" . gettype($curlHandle) . "' provided.");
		}
		$this->curlHandle = $curlHandle;
	}

	/**
	 * Gets Options
	 *
	 * @return Options
	 */
	public function getOptions() {
		return $this->options;
	}

	/**
	 * Sets Options
	 *
	 * @param $options Options
	 */
	public function setOptions(Options $options) {
		$this->options = $options;
	}

	/**
	 * Sets up cURL ready for executing
	 */
	protected function init() {
		//To start with, disable FOLLOWLOCATION since we'll handle it
		curl_setopt($this->curlHandle, CURLOPT_FOLLOWLOCATION, false);

		//Always return the transfer
		curl_setopt($this->curlHandle, CURLOPT_RETURNTRANSFER, true);

		//Force IPv4, since this class isn't yet comptible with IPv6
		$curlVersion = curl_version();
		if ($curlVersion['features'] & CURLOPT_IPRESOLVE) {
			curl_setopt($this->curlHandle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
		}
	}

	public function prepare(string $url) {
		//Validate the URL
		$url = Url::validateUrl($url, $this->options);

		//Are there credentials, but we don't want to send them?
		if (!$this->options->getSendCredentials() &&
			(array_key_exists('user', $url) || array_key_exists('pass', $url))) {
			throw new InvalidURLException("Credentials passed in but 'sendCredentials' is set to false");
		}

		if ($this->options->getPinDns()) {
			$host = $url['host'];
			if (strpos($host, ':') !== false)
				throw new InvalidURLException("Malformed hostname: {$host}");
			$ips = implode(',', $url['ips']);
			$resolutions = array_map(function ($port) use ($host, $ips) {
				return "{$host}:{$port}:{$ips}";
			}, $this->options->getList('whitelist', 'port'));
			if (!curl_setopt($this->curlHandle, CURLOPT_RESOLVE, $resolutions))
				throw new Exception("Unable to override cURL DNS resolution");
		}

		curl_setopt($this->curlHandle, CURLOPT_URL, $url['cleanUrl']);
		$headers = $this->options->getHeaders();
		if ($headers !== null)
			curl_setopt($this->curlHandle, CURLOPT_HTTPHEADER, $headers);
	}

	/**
	 * Exectutes a cURL request, whilst checking that the
	 * URL abides by our whitelists/blacklists
	 *
	 * @param $url        string
	 * @param $curlHandle resource         optional - Incase called on an object rather than statically
	 * @param $options    Options optional
	 * @return bool
	 * @throws InvalidURLException
	 * @throws \SafeCurl\Exception
	 */
	public static function execute($url, $curlHandle = null, Options $options = null) {
		$safeCurl = new SafeCurl($curlHandle, $options);

		//Backup the existing URL
		$originalUrl = $url;

		//Execute, catch redirects and validate the URL
		$redirected     = false;
		$redirectCount  = 0;
		$redirectLimit  = $safeCurl->getOptions()->getFollowLocationLimit();
		$followLocation = $safeCurl->getOptions()->getFollowLocation();
		do {
			$safeCurl->prepare($url);
			// in case of `CURLINFO_REDIRECT_URL` isn't defined
			curl_setopt($curlHandle, CURLOPT_HEADER, true);

			//Execute the cURL request
			$response = curl_exec($curlHandle);

			//Check for any errors
			if (curl_errno($curlHandle)) {
				throw new Exception("cURL Error: " . curl_error($curlHandle));
			}

			//Check for an HTTP redirect
			if ($followLocation) {
				$statusCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);
				switch ($statusCode) {
					case 301:
					case 302:
					case 303:
					case 307:
					case 308:
						if ($redirectLimit == 0 || ++$redirectCount < $redirectLimit) {
							//Redirect received, so rinse and repeat
							$url = curl_getinfo($curlHandle, CURLINFO_REDIRECT_URL);
							$redirected = true;
						} else {
							throw new Exception("Redirect limit '$redirectLimit' hit");
						}
						break;
					default:
						$redirected = false;
				}
			}
		} while ($redirected);

		return $response;
	}
}



