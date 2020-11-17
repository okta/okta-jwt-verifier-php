<?php

declare(strict_types=1);

namespace Test\Unit\Adaptor;

use Okta\JwtVerifier\Adaptor\FirebasePhpJwt;
use Test\BaseTestCase;

class FirebasePhpJwtTest extends BaseTestCase
{
    /**
     * @var FirebasePhpJwt
     */
    protected $adaptor;

    public function setUp(): void
    {
        parent::setUp();

        $this->adaptor = new FirebasePhpJwt();
    }

    /**
     * @test
     */
    public function can_parse_key_set(): void
    {
        $jwks = file_get_contents(__DIR__ . '/Resources/jwks.json');

        $parsed = $this->adaptor->parseKeySet($jwks);
        self::assertArrayHasKey(0, $parsed);
        self::assertArrayHasKey('my-key', $parsed);

        $key0 = openssl_pkey_get_details($parsed[0]);
        self::assertSame($key0['key'], file_get_contents(__DIR__ . '/Resources/public_key-0'));

        $myKey = openssl_pkey_get_details($parsed['my-key']);
        self::assertSame($myKey['key'], file_get_contents(__DIR__ . '/Resources/public_key-my-key'));
    }

    /**
     * @test
     */
    public function can_decode(): void
    {
        $jwks = file_get_contents(__DIR__ . '/Resources/jwks.json');
        $keys = $this->adaptor->parseKeySet($jwks);
        $jwt = $this->adaptor->decode(
            file_get_contents(__DIR__ . '/Resources/jwt'),
            $keys
        );

        self::assertEquals(
            [
                'extra' => 'data',
                'iat' => 1577836800,
                'exp' => 4102444800
            ],
            $jwt->getClaims()
        );
    }
}
