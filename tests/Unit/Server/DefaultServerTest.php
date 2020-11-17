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

namespace Test\Unit\Server;

use Http\Mock\Client;
use Okta\JwtVerifier\Adaptor\Adaptor;
use Okta\JwtVerifier\Adaptor\FirebasePhpJwt;
use Okta\JwtVerifier\Server\DefaultServer;
use Okta\JwtVerifier\Server\Discovery\Discovery;
use Okta\JwtVerifier\Server\Discovery\Oauth;
use Okta\JwtVerifier\JwtVerifier;
use Okta\JwtVerifier\Request;
use Okta\JwtVerifier\Server\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Test\BaseTestCase;

class DefaultServerTest extends BaseTestCase
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
        $this->adaptor = $this->createMock(FirebasePhpJwt::class);
    }

    /** @test */
    public function can_get_issuer_from_constructor(): void
    {
        $server = new DefaultServer(
            'test-issuer',
            $this->discovery,
            $this->request
        );

        self::assertSame(
            'test-issuer',
            $server->getIssuer(),
            'Does not return issuer correctly'
        );
    }

    /** @test */
    public function can_get_discovery_from_constructor(): void
    {
        $server = new DefaultServer(
            'test-issuer',
            $this->discovery,
            $this->request
        );

        self::assertSame(
            $this->discovery,
            $server->getDiscovery(),
            'Does not return discovery correctly'
        );
    }

    protected function configureMetaDataResponse($response): void
    {
        $this->discovery
            ->expects(self::once())
            ->method('getWellKnown')
            ->willreturn('/test-well-known');

        $this->request
            ->expects(self::once())
            ->method('setUrl')
            ->with('https://my.issuer.com/test-well-known')
            ->willReturnSelf();

        $this->request
            ->expects(self::once())
            ->method('get')
            ->willReturn($this->response);

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects(self::once())
            ->method('getContents')
            ->willReturn($response);

        $this->response
            ->expects(self::once())
            ->method('getBody')
            ->willreturn($stream);
    }

    /** @test */
    public function will_get_meta_data_from_issuer_and_well_known(): void
    {
        $this->configureMetaDataResponse('{"jwks_uri": "https://example.com"}');

        $server = new DefaultServer(
            'https://my.issuer.com',
            $this->discovery,
            $this->request
        );

        $metaData = $server->getMetaData();

        self::assertSame(
            'https://example.com',
            $metaData->jwks_uri
        );
    }

    /**
     * @test
     *@dataProvider invalidJsonProvider
     */
    public function will_throw_exception_when_meta_data_is_not_json_string(
        $response,
        string $message
    ): void {
        $this->configureMetaDataResponse($response);

        $server = new DefaultServer(
            'https://my.issuer.com',
            $this->discovery,
            $this->request
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches($message);

        $server->getMetaData();
    }

    public function invalidJsonProvider(): array
    {
        return [
            'integer' => [
                123,
                '~did not receive json~'
            ],
            'null' => [
                null,
                '~did not receive json~'
            ],
            'array' => [
                ['test'],
                '~did not receive json~'
            ],
            'object' => [
                new \stdClass,
                '~did not receive json~'
            ],
            'invalid json' => [
                '{this is not valid}',
                '~did not receive a valid json object~'
            ],
            'not a json object' => [
                '["this is an array"]',
                '~did not receive a valid json object~'
            ],
        ];
    }

    protected function configureJWKSResponse($response): void
    {
        $this->discovery
            ->expects(self::once())
            ->method('getWellKnown')
            ->willreturn('/test-well-known');

        $this->request
            ->expects(self::exactly(2))
            ->method('setUrl')
            ->withConsecutive(
                ['https://my.issuer.com/test-well-known'],
                ['https://my.issuer.com/jwks.json']
            )
            ->willReturnSelf();

        $metaDataResponse = $this->createMock(ResponseInterface::class);
        $metaDataStream = $this->createMock(StreamInterface::class);
        $metaDataStream->expects(self::once())
            ->method('getContents')
            ->willReturn('{"jwks_uri": "https://my.issuer.com/jwks.json"}');
        $metaDataResponse
            ->method('getBody')
            ->willreturn($metaDataStream);

        $jwksResponse = $this->createMock(ResponseInterface::class);
        $jwksStream = $this->createMock(StreamInterface::class);
        $jwksStream->expects(self::once())
            ->method('getContents')
            ->willReturn($response);
        $jwksResponse
            ->expects(self::once())
            ->method('getBody')
            ->willreturn($jwksStream);

        $this->request
            ->method('get')
            ->willReturnOnConsecutiveCalls($metaDataResponse, $jwksResponse);
    }

    /** @test */
    public function will_get_jwks_from_well_known(): void
    {
        $this->configureJWKSResponse('{"keys": ["test"]}');

        $server = new DefaultServer(
            'https://my.issuer.com',
            $this->discovery,
            $this->request
        );

        $keys = $server->getKeys();

        self::assertEquals(
            '{"keys": ["test"]}',
            $keys
        );
    }
}
