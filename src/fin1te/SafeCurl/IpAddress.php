<?php
namespace fin1te\SafeCurl;

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