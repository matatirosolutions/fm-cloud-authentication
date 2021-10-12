# FileMaker cloud authentication #

The FileMaker Data API uses a realtively simple authentication pattern when using a self hosted server. Post valid credentials to the server, receive a token, use that as a bearer token for subsequent requests.

With FileMaker Cloud 2 however, the process is made somewhat more complex through the use of Cognito, the AWS credentials management system. This library simplifies that process to be as straight-forward as the on-premise version. 

## Installation ##

```bash
composer require matatirosolutions/fm-cloud-authentication
```
## Usage ##

```php
$credentials = new \MSDev\FMCloudAuthenticator\Credentials(
    'your-fm-cloud-server',
    'your-fmrest-user',
    'your-fmrest-password',
    \MSDev\FMCloudAuthenticator\Credentials::DAPI,
    'your-database'
);

$authenticator = new \MSDev\FMCloudAuthenticator\Authenticate();
$token = $authenticator->fetchToken($credentials);
```
`$token` should now contain a bearer token which you can use for subsequent requests as usual. 
 
At present only the Data API is supported, however we plan to extend this to the Admin API as well.

## Contact ##

See this [blog post](https://msdev.co.uk/fm-cloud-authentication) for more details.

Steve Winter  
Matatiro Solutions  
steve@msdev.co.uk