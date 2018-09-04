<?php

namespace Okta\JwtVerifier\Adaptors;

use Okta\JwtVerifier\Jwt;
use Okta\JwtVerifier\Request;

class LcobucciJwt implements Adaptor
{
    /**
     * @var Request
     */
    protected $request;

    /**
     * @param Request $request
     */
    public function __construct(Request $request = null)
    {
        $this->request = $request ?: new Request();
    }

    /**
     * @param string $jku
     * @return object|array
     */
    public function getKeys($jku)
    {
        $keys = json_decode($this->request->setUrl($jku)->get()->getBody()->getContents());

        return $this->parseKeySet($keys);
    }

    /**
     * @param string $jwt
     * @param array $keys
     * @return Jwt
     */
    public function decode($jwt, $keys)
    {
        $decoded = (new \Lcobucci\JWT\Parser())->parse($jwt);

        return (new Jwt($jwt, $decoded->getClaims()));
    }

    /**
     * @return bool
     */
    public static function isPackageAvailable()
    {
        return
            class_exists(\Lcobucci\JWT\Parsing\Decoder::class) &&
            class_exists(\Lcobucci\JWT\Parser::class);
    }

    /**
     * Parse a set of JWK keys
     * @param $source
     * @return array an associative array represents the set of keys
     */
    public function parseKeySet($source)
    {
        $keys = [];
        if (is_string($source)) {
            $source = json_decode($source, true);
        } else if (is_object($source)) {
            if (property_exists($source, 'keys'))
                $source = (array)$source;
            else
                $source = [$source];
        }
        if (is_array($source)) {
            if (isset($source['keys']))
                $source = $source['keys'];

            foreach ($source as $k => $v) {
                if (!is_string($k)) {
                    if (is_array($v) && isset($v['kid']))
                        $k = $v['kid'];
                    elseif (is_object($v) && property_exists($v, 'kid'))
                        $k = $v->{'kid'};
                }
                try {
                    $v = $this->parseKey($v);
                    $keys[$k] = $v;
                } catch (\UnexpectedValueException $e) {
                    //Do nothing
                }
            }
        }
        if (0 < count($keys)) {
            return $keys;
        }
        throw new \UnexpectedValueException('Failed to parse JWK');
    }

    /**
     * Parse a JWK key
     * @param $source
     * @return resource|array an associative array represents the key
     */
    public function parseKey($source)
    {
        if (!is_array($source))
            $source = (array)$source;
        if (!empty($source) && isset($source['kty']) && isset($source['n']) && isset($source['e'])) {
            switch ($source['kty']) {
                case 'RSA':
                    if (array_key_exists('d', $source))
                        throw new \UnexpectedValueException('Failed to parse JWK: RSA private key is not supported');

                    $pem = $this->createPemFromModulusAndExponent($source['n'], $source['e']);
                    $pKey = openssl_pkey_get_public($pem);
                    if ($pKey !== false)
                        return $pKey;
                    break;
                default:
                    //Currently only RSA is supported
                    break;
            }
        }

        throw new \UnexpectedValueException('Failed to parse JWK');
    }

    /**
     *
     * Create a public key represented in PEM format from RSA modulus and exponent information
     *
     * @param string $n the RSA modulus encoded in Base64
     * @param string $e the RSA exponent encoded in Base64
     * @return string the RSA public key represented in PEM format
     */
    protected function createPemFromModulusAndExponent($n, $e)
    {
        $decoder = new \Lcobucci\JWT\Parsing\Decoder();

        $modulus = $decoder->base64UrlDecode($n);
        $publicExponent = $decoder->base64UrlDecode($e);

        $components = [
            'modulus' => pack('Ca*a*', 2, $this->encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, $this->encodeLength(strlen($publicExponent)), $publicExponent)
        ];

        $RSAPublicKey = pack(
            'Ca*a*a*',
            48,
            $this->encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );


        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $RSAPublicKey = chr(0) . $RSAPublicKey;
        $RSAPublicKey = chr(3) . $this->encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;

        $RSAPublicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $RSAPublicKey)),
            $rsaOID . $RSAPublicKey
        );

        $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $RSAPublicKey;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.
     * See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3}
     * for more information.
     *
     * @access private
     * @param int $length
     * @return string
     */
    protected function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
