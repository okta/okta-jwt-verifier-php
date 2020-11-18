<?php
/******************************************************************************
 * Copyright 2017 Okta, Inc.                                                  *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 ******************************************************************************/

namespace Test\Unit;

use DomainException;
use Http\Mock\Client;
use Okta\JwtVerifier\Adaptor\Adaptor;
use Okta\JwtVerifier\Adaptor\FirebasePhpJwt;
use Okta\JwtVerifier\Jwt;
use Okta\JwtVerifier\Server\Discovery\Discovery;
use Okta\JwtVerifier\JwtVerifier;
use Okta\JwtVerifier\Request;
use Okta\JwtVerifier\Server\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ResponseInterface;
use Test\BaseTestCase;

class JwtVerifierTest extends BaseTestCase
{
    /**
     * @var MockObject|Server
     */
    protected $server;

    /**
     * @var MockObject|Request
     */
    protected $request;

    /**
     * @var MockObject|ResponseInterface
     */
    protected $response;

    /**
     * @var MockObject|Discovery
     */
    protected $discovery;

    /**
     * @var MockObject|Adaptor
     */
    protected $adaptor;

    public function setUp(): void
    {
        parent::setUp();

        $this->server = $this->createMock(Server::class);
        $this->request = $this->createMock(Request::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->discovery = $this->createMock(Discovery::class);
        $this->adaptor = $this->createMock(Adaptor::class);
    }

    /** @test */
    public function can_get_server_from_constructor(): void
    {
        $verifier = new JwtVerifier($this->server);

        self::assertSame(
            $this->server,
            $verifier->getServer(),
            'Does not return server correctly'
        );
    }

    /** @test */
    public function can_get_adaptor_from_constructor(): void
    {
        $verifier = new JwtVerifier(
            $this->server,
            $this->adaptor
        );

        self::assertSame(
            $this->adaptor,
            $verifier->getAdaptor(),
            'Does not return adaptor correctly'
        );
    }

    /** @test */
    public function defaults_to_firebase_adaptor(): void
    {
        $verifier = new JwtVerifier($this->server);

        self::assertInstanceOf(
            FirebasePhpJwt::class,
            $verifier->getAdaptor(),
            'Does not default to Firebase adaptor'
        );
    }

    protected function configureJwt(array $claims): Jwt
    {
        $this->server
            ->expects(self::once())
            ->method('getKeys')
            ->willReturn('my keys');

        $this->adaptor
            ->expects(self::once())
            ->method('parseKeySet')
            ->with('my keys')
            ->willReturn(['my keys']);

        $jwt = $this->createMock(Jwt::class);

        $this->adaptor
            ->expects(self::once())
            ->method('decode')
            ->with('my token', ['my keys'])
            ->willReturn($jwt);

        $jwt->expects(self::once())->method('getClaims')->willReturn($claims);

        return $jwt;
    }

    /** @test */
    public function can_verify_empty_token_if_no_claims_registered(): void
    {
        $jwt = $this->configureJwt([]);

        $verifier = new JwtVerifier($this->server, $this->adaptor);

        self::assertSame(
            $jwt,
            $verifier->verify('my token')
        );
    }

    /** @test */
    public function can_verify_empty_token_with_claims_registered(): void
    {
        $jwt = $this->configureJwt([]);

        $verifier = new JwtVerifier($this->server, $this->adaptor, [
            JwtVerifier::VALIDATE_NONCE => 'my nonce',
            JwtVerifier::VALIDATE_AUDIENCE => 'my audience',
            JwtVerifier::VALIDATE_CLIENT_ID => 'my client id',
        ]);

        self::assertSame(
            $jwt,
            $verifier->verify('my token')
        );
    }

    /** @test */
    public function can_verify_nonce(): void
    {
        $this->configureJwt(['nonce' => 'correct nonce']);

        $verifier = new JwtVerifier($this->server, $this->adaptor, [
            JwtVerifier::VALIDATE_NONCE => 'my nonce',
        ]);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessageMatches('~Nonce does not match what is expected~');

        $verifier->verify('my token');
    }

    /** @test */
    public function can_verify_audience(): void
    {
        $this->configureJwt(['aud' => 'correct audience']);

        $verifier = new JwtVerifier($this->server, $this->adaptor, [
            JwtVerifier::VALIDATE_AUDIENCE => 'my audience',
        ]);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessageMatches('~Audience does not match what is expected~');

        $verifier->verify('my token');
    }

    /** @test */
    public function can_verify_client_id(): void
    {
        $this->configureJwt(['cid' => 'correct audience']);

        $verifier = new JwtVerifier($this->server, $this->adaptor, [
            JwtVerifier::VALIDATE_CLIENT_ID => 'my audience',
        ]);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessageMatches('~ClientId does not match what is expected~');

        $verifier->verify('my token');
    }
}
