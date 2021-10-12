<?php
declare(strict_types=1);

namespace MSDev\FMCloudAuthenticator;

use MSDev\FMCloudAuthenticator\Exception\AuthenticationException;

class Credentials
{
    public const DAPI = 'DAPI';
    public const ADMIN = 'Admin';

    private string $serverAddress;

    private string $clarisIdUsername;

    private string $clarisIdPassword;

    private string $tokenType;

    private ?string $database;

    public function __construct(
        string $serverAddress,
        string $clarisIdUsername,
        string $clarisIdPassword,
        string $tokenType = self::DAPI,
        ?string $database = null
    ) {
        $this->serverAddress = $serverAddress;
        $this->clarisIdUsername = $clarisIdUsername;
        $this->clarisIdPassword = $clarisIdPassword;
        $this->database = $database;
        $this->tokenType = $tokenType;
    }

    public function getServerAddress(): string
    {
        return $this->serverAddress;
    }

    public function getClarisIdUsername(): string
    {
        return $this->clarisIdUsername;
    }

    public function getClarisIdPassword(): string
    {
        return $this->clarisIdPassword;
    }

    public function getSessionEndpoint(): string
    {
        $base = $this->verifyAddress();
        if(self::DAPI === $this->tokenType) {
            if(null === $this->database) {
                throw new AuthenticationException('No database defined in credentials');
            }

            return sprintf('%s/fmi/data/vLatest/databases/%s/sessions', $base, $this->database);
        }


    }

    private function verifyAddress(): string
    {
        $address = $this->serverAddress;
        if(strpos($this->serverAddress, 'http') !== 0) {
            $address = 'http://' . $this->serverAddress;
        }

        if('/' === substr($this->serverAddress, -1)) {
            return substr($address, 0, -1);
        }
        return $address;
    }

}