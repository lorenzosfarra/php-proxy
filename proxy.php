<?php
/*
 * Author:
 *    Robin Zon <https://github.com/ZonRobin>
 *
 * Content-type POST improvements:
     Lorenzo Sfarra <https://lorenzosfarra.com>
 *
 * Credits to:
 *    https://github.com/cowboy/php-simple-proxy/
 *    https://gist.github.com/iovar
 *
 * Usage:
 *    To call this script two headers must be sent
 *        HTTP_PROXY_AUTH           Access key for the proxy (should be changed)
 *        HTTP_PROXY_TARGET_URL     URL to be called by this script
 *
 * Debug:
 *    To debug, send HTTP_PROXY_DEBUG header with any non-zero value
 *
 * Compatibility:
 *    PHP 5.4
 *    libcurl
 *    PHP safe_mode disabled
 */
//----------------------------------------------------------------------------------

require 'random_user_agent.php';

// Your private auth key
define('AUTH_KEY', 'm8kDEtZefDk3Np7sHDmGG6J7fP6jRqrg43CJEX4kmWuCc');

// Name of the proxy auth key header
define('HTTP_PROXY_AUTH', 'HTTP_PROXY_AUTH');

// Name of the target url header
define('HTTP_PROXY_TARGET_URL', 'HTTP_PROXY_TARGET_URL');

// Name of remote debug header
define('HTTP_PROXY_DEBUG', 'HTTP_PROXY_DEBUG');

// Uncomment this to simulate target header
// $_SERVER[HTTP_PROXY_TARGET_URL] = 'https://github.com/';

// Uncomment this to simulate auth key (or to disable the need of passing the key with each request)
// $_SERVER[HTTP_PROXY_AUTH] = AUTH_KEY;

// Uncomment this to enable debug mode
// $_SERVER[HTTP_PROXY_DEBUG] = '1';

// If true, PHP safe mode compatibility will not be checked (you may not need it if no POST files are sent over proxy)
define('IGNORE_SAFE_MODE', true);

// Line break for debug purposes
define('HR', PHP_EOL . PHP_EOL . '----------------------------------------------' . PHP_EOL . PHP_EOL);


//----------------------------------------------------------------------------------
/**
 * @param mixed $variable
 * @param mixed $default
 * @return mixed
 */
function ri(&$variable, $default = null)
{
    if (isset($variable)) {
        return $variable;
    } else {
        return $default;
    }
}


/**
 * @param string $message
 */
function exitWithError($message = 'unknown')
{
    echo 'PROXY ERROR: ' . $message;
    http_response_code(500);
    exit(500);
}


/**
 * @return array
 */
function getSkippedHeaders()
{
    return array(HTTP_PROXY_TARGET_URL, HTTP_PROXY_AUTH, HTTP_PROXY_DEBUG, 'HTTP_HOST', 'HTTP_ACCEPT_ENCODING');
}


if (!function_exists('errorHandler')) {
    /**
     * @param int $code
     * @param string $message
     * @param string $file
     * @param string $line
     */
    function errorHandler($code, $message, $file, $line)
    {
        exitWithError($message . ' in ' . $file . ' at line ' . $line);
    }
}


if (!function_exists('exceptionHandler')) {
    /**
     * @param Exception $ex
     */
    function exceptionHandler(Exception $ex)
    {
        exitWithError($ex->getMessage() . ' in ' . $ex->getFile() . ' at line ' . $ex->getLine());
    }
}


//----------------------------------------------------------------------------------

// Compatibility checks

if (!IGNORE_SAFE_MODE && function_exists('ini_get') && ini_get('safe_mode')) {
    exitWithError('Safe mode is enabled, this may cause problems with uploading files');
}

if (!function_exists('curl_init')) {
    exitWithError('libcurl is not installed on this server');
}

if (class_exists('CURLFile')) {
    define('CURLFILE', true);
} else {
    define('CURLFILE', false);
}

//----------------------------------------------------------------------------------

set_error_handler('errorHandler', E_ALL);
set_exception_handler('exceptionHandler');

//----------------------------------------------------------------------------------

// Check for auth token
if (ri($_SERVER[HTTP_PROXY_AUTH]) !== AUTH_KEY) {
    exitWithError(HTTP_PROXY_AUTH . ' header is invalid');
}

// Check for debug token
if (!empty($_SERVER[HTTP_PROXY_DEBUG])) {
    $debug = true;
} else {
    $debug = false;
}

// Get target URL
$targetURL = ri($_SERVER[HTTP_PROXY_TARGET_URL]);
if (empty($targetURL)) {
    exitWithError(HTTP_PROXY_TARGET_URL . ' header is empty');
}
if (filter_var($targetURL, FILTER_VALIDATE_URL) === false) {
    exitWithError(HTTP_PROXY_TARGET_URL . ' "' . $targetURL . '" is invalid');
}

//--------------------------------

// Add GET params to target URL
if (!empty($_SERVER['QUERY_STRING'])) {
    $targetURLParts = parse_url($targetURL);
    if (!empty($targetURLParts['query'])) {
        $targetURL = $targetURL . '&' . $_SERVER['QUERY_STRING'];
    } else {
        $targetURL = trim($targetURL, '\?');
        $targetURL = $targetURL . '?' . $_SERVER['QUERY_STRING'];
    }
}

//-------------------------------

// Create CURL request
$request = curl_init($targetURL);

//-------------------------------

$is_www_encoded = false;
//--------------------------------

// Parse request headers
$httpHeaders = array();
$httpHeadersAll = array();
foreach ($_SERVER as $key => $value) {
    if ((strpos($key, 'HTTP_') === 0) || ($key === 'CONTENT_LENGTH') || ($key === 'CONTENT_TYPE')) {
        $header_key = str_replace(
            '_',
            '-',
            ucwords(strtolower(str_replace('HTTP_', '', $key)), '_')
        );
        $header = "$header_key: $value";
        if (
            (strtoupper($key) === 'CONTENT_TYPE') &&
            (strtolower($value) === 'application/x-www-form-urlencoded')
        ) {
            $is_www_encoded = true;
        }

        if (!in_array($key, getSkippedHeaders())) {
            $httpHeaders[] = $header;
        }

        $httpHeadersAll[] = $header;
    }
}

// Set input data
$requestMethod = strtoupper(ri($_SERVER['REQUEST_METHOD']));
if ($requestMethod === "PUT" || $requestMethod === "PATCH") {
    curl_setopt($request, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
} elseif ($requestMethod === "POST") {
    $data = array();

    if (!empty($_FILES)) {
        if (!CURLFILE) {
            curl_setopt($request, CURLOPT_SAFE_UPLOAD, false);
        }

        foreach ($_FILES as $fileName => $file) {
            $filePath = realpath($file['tmp_name']);

            if (CURLFILE) {
                $data[$fileName] = new CURLFile($filePath);
            } else {
                $data[$fileName] = '@' . $filePath;
            }
        }
    }

    $post_params = $data + $_POST;
    if ($is_www_encoded) {
        $post_params = http_build_query($post_params);
    }
    curl_setopt($request, CURLOPT_POSTFIELDS, $post_params);
}

curl_setopt_array($request, [
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HEADER => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLINFO_HEADER_OUT => true,
    CURLOPT_HTTPHEADER => $httpHeaders
]);

//----------------------------------

// Get response
$response = curl_exec($request);

$headerSize = curl_getinfo($request, CURLINFO_HEADER_SIZE);
$responseHeader = substr($response, 0, $headerSize);
$responseBody = substr($response, $headerSize);
$responseInfo = curl_getinfo($request);
$responseCode = ri($responseInfo['http_code'], 500);
$requestHeaders = preg_split('/[\r\n]+/', ri($responseInfo['request_header'], ''));
if ($responseCode == 0) {
    $responseCode = 404;
}

// Get real target URL after all redirects
$finalRequestURL = curl_getinfo($request, CURLINFO_EFFECTIVE_URL);
if (!empty($finalRequestURL)) {
    $finalRequestURLParts = parse_url($finalRequestURL);
    $finalURL = ri($finalRequestURLParts['scheme'], 'http') . '//' .
        ri($finalRequestURLParts['host']) . ri($finalRequestURLParts['path'], '');
}

curl_close($request);

//----------------------------------

// Split header text into an array.
$responseHeaders = preg_split('/[\r\n]+/', $responseHeader);
// Pass headers to output
foreach ($responseHeaders as $header) {
    // Pass following headers to response
    if (preg_match('/^(?:Content-Type|Content-Language|Content-Security|X)/i', $header)) {
        header($header);
    } // Replace cookie domain and path
    elseif (strpos($header, 'Set-Cookie') !== false) {
        $header = preg_replace('/((?>domain)\s*=\s*)[^;\s]+/', '\1.' . $_SERVER['HTTP_HOST'], $header);
        $header = preg_replace('/\s*;?\s*path\s*=\s*[^;\s]+/', '', $header);
        header($header, false);
    } // Decode response body if gzip encoding is used
    elseif ($header === 'Content-Encoding: gzip') {
        $responseBody = gzdecode($responseBody);
    }
}

//----------------------------------

if ($debug) {
    echo 'Headers sent to proxy' . PHP_EOL . PHP_EOL;
    echo implode($httpHeadersAll, PHP_EOL);
    echo HR;

    echo '$_GET sent to proxy' . PHP_EOL . PHP_EOL;
    print_r($_GET);
    echo HR;

    echo '$_POST sent to proxy' . PHP_EOL . PHP_EOL;
    print_r($_POST);
    echo HR;

    echo 'Headers sent to target' . PHP_EOL . PHP_EOL;
    echo implode($requestHeaders, PHP_EOL);
    echo HR;

    echo 'Headers received from target' . PHP_EOL . PHP_EOL;
    echo implode($responseHeaders, PHP_EOL);
    echo HR;

    echo 'Headers sent from proxy to client' . PHP_EOL . PHP_EOL;
    echo implode(headers_list(), PHP_EOL);
    echo HR;

    echo 'Body sent from proxy to client' . PHP_EOL . PHP_EOL;
    echo $responseBody;
} else {
    http_response_code($responseCode);
    exit($responseBody);
}
