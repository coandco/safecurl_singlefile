<?php
namespace fin1te\SafeCurl;

use fin1te\SafeCurl\Exception\InvalidOptionException;

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
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
     */
    public function enableFollowLocation() {
        $this->followLocation = true;

        return $this;
    }

    /**
     * Disables following redirects
     *
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
     */
    public function enableSendCredentials() {
        $this->sendCredentials = true;

        return $this;
    }

    /**
     * Disable sending of credentials
     *
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
     */
    public function enablePinDns() {
        $this->pinDns = true;

        return $this;
    }

    /**
     * Disable DNS pinning
     *
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
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
     * @return fin1te\SafeCurl\Options
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