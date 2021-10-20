<?php
declare(strict_types=1);

namespace MSDev\FMCloudAuthenticator;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use MSDev\FMCloudAuthenticator\Exception\AuthenticationException;
use Throwable;

class Authenticate
{
    private const USER_POOL_ENDPOINT = 'https://www.ifmcloud.com/endpoint/userpool/2.2.0.my.claris.com.json';

    private ?string $cognitoRegion = null;

    private string $cognitoClientId;

    private string $cognitoPoolId;

    private CognitoIdentityProviderClient $client;

    /**
     * @throws AuthenticationException
     */
    public function fetchToken(Credentials $credentials): string
    {
        try {
            return $this->getFileMakerToken($credentials, $this->getCognitoToken($credentials));
        } catch (Exception | Throwable $except) {
            throw new AuthenticationException($except->getMessage(), $except->getCode(), $except);
        }
    }

    /**
     * @throws AuthenticationException
     * @throws Exception
     */
    private function getCognitoToken(Credentials $credentials): string
    {
        $clarisCognitoConfigObject = $this->fetchFileMakerCognitoPoolData();

        $cognitoClient = new CognitoIdentityProviderClient([
            'region' => $clarisCognitoConfigObject->data->Region,
            'version' => 'latest',
            'credentials' => false,
        ]);

            $srp = new AWSCognitoIdentitySRP(
                $cognitoClient,
                $clarisCognitoConfigObject->data->Client_ID,
                $clarisCognitoConfigObject->data->UserPool_ID
            );

            $result = $srp->authenticateUser(
                $credentials->getClarisIdUsername(),
                $credentials->getClarisIdPassword()
            );

        return $result->get('AuthenticationResult')['IdToken'];
    }
    
    /**
     * @throws AuthenticationException
     */
    private function fetchFileMakerCognitoPoolData(): object
    {
        $client = new Client();
        try {
            $response = $client->get(self::USER_POOL_ENDPOINT);
            return  json_decode($response->getBody()->getContents(), false, 512, JSON_THROW_ON_ERROR);
        } catch (GuzzleException | JsonException $except) {
            throw new AuthenticationException('Unable to retrieve Cognito data', $except->getCode(), $except);
        }
    }

    /**
     * @throws AuthenticationException
     */
    private function getFileMakerToken(Credentials $credentials, string $cognitoToken): string
    {
        $client = new Client();
        try {
            $response = $client->post($credentials->getSessionEndpoint(), [
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Authorization' => sprintf('FMID %s', $cognitoToken)
                ]
            ]);
            $json = json_decode($response->getBody()->getContents(), false, 512, JSON_THROW_ON_ERROR);
            return $json->response->token;
        } catch (GuzzleException | JsonException $except) {
            throw new AuthenticationException('Unable to retrieve Cognito data', $except->getCode(), $except);
        }
    }
}
