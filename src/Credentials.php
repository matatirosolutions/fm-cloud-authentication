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

    public function getClarisIdUsername(): string
    {
        return $this->clarisIdUsername;
    }

    public function getClarisIdPassword(): string
    {
        return $this->clarisIdPassword;
    }

    /**
     * @throws AuthenticationException
     */
    public function getSessionEndpoint(): string
    {
        $base = $this->verifyAddress();
        if(self::DAPI === $this->tokenType) {
            if(null === $this->database) {
                throw new AuthenticationException('No database defined in credentials');
            }

            return sprintf('%s/fmi/data/vLatest/databases/%s/sessions', $base, $this->database);
        }
        if(self::ADMIN === $this->tokenType) {
            throw new AuthenticationException('Currently only DAPI tokens are supported');
        }
        throw new AuthenticationException(
            sprintf("Unknown token type'%s' requested", $this->tokenType)
        );
    }

    private function verifyAddress(): string
    {
        $address = $this->serverAddress;
        if(strpos($this->serverAddress, 'http') !== 0) {
            $address = 'https://' . $this->serverAddress;
        }

        if('/' === substr($this->serverAddress, -1)) {
            return substr($address, 0, -1);
        }
        return $address;
    }

}
