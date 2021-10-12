<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class AuthenticationTest extends TestCase
{
    public function testGetToken(): void
    {
        $credentials = new \MSDev\FMCloudAuthenticator\Credentials(
            'your-fm-cloud-server',
            'your-fmrest-user',
            'your-fmrest-password',
            \MSDev\FMCloudAuthenticator\Credentials::DAPI,
            'your-database'
        );

        $authenticator = new \MSDev\FMCloudAuthenticator\Authenticate();
        $authenticator->fetchToken($credentials);
    }

}
