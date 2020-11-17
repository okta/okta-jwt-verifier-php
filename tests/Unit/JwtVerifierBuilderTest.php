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

use InvalidArgumentException;
use Okta\JwtVerifier\Adaptor\Adaptor;
use Okta\JwtVerifier\Server\Discovery\Oauth;
use Okta\JwtVerifier\JwtVerifier;
use Okta\JwtVerifier\JwtVerifierBuilder;
use Test\BaseTestCase;

class JwtVerifierBuilderTest extends BaseTestCase
{
    /** @test */
    public function when_setting_issuer_self_is_returned(): void
    {
        $verifier = new JwtVerifierBuilder();
        self::assertInstanceOf(
            JwtVerifierBuilder::class,
            $verifier->setIssuer('issuer'),
            'Setting the issuer does not return self.'
        );
    }

    /** @test */
    public function when_setting_discovery_self_is_returned(): void
    {
        $verifier = new JwtVerifierBuilder();
        self::assertInstanceOf(
            JwtVerifierBuilder::class,
            $verifier->setDiscovery($this->createMock(Oauth::class)),
            'Settings discovery does not return self.'
        );
    }

    /** @test */
    public function when_setting_adaptor_self_is_returned(): void
    {
        $verifier = new JwtVerifierBuilder();
        self::assertInstanceOf(
            JwtVerifierBuilder::class,
            $verifier->setAdaptor($this->createMock(Adaptor::class)),
            'Settings adaptor does not return self.'
        );
    }

    /** @test */
    public function when_setting_audience_self_is_returned(): void
    {
        $verifier = new JwtVerifierBuilder();
        self::assertInstanceOf(
            JwtVerifierBuilder::class,
            $verifier->setAudience('test'),
            'Settings audience does not return self.'
        );
    }

    /** @test */
    public function when_setting_client_id_self_is_returned(): void
    {
        $verifier = new JwtVerifierBuilder();
        self::assertInstanceOf(
            JwtVerifierBuilder::class,
            $verifier->setClientId('test'),
            'Settings client id does not return self.'
        );
    }

    /** @test */
    public function when_setting_nonce_id_self_is_returned(): void
    {
        $verifier = new JwtVerifierBuilder();
        self::assertInstanceOf(
            JwtVerifierBuilder::class,
            $verifier->setNonce('test'),
            'Settings nonce does not return self.'
        );
    }

    /** @test */
    public function build_throws_exception_if_issuer_not_set(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectErrorMessageMatches('~^Your Issuer is missing~');
        $verifier = new JwtVerifierBuilder();
        $verifier->build();
    }

    /** @test */
    public function build_throws_exception_if_issuer_does_not_start_with_https(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectErrorMessageMatches('~^Your Issuer must start with https~');
        $verifier = new JwtVerifierBuilder();
        $verifier->setIssuer('http://test');
        $verifier->build();
    }

    /** @test */
    public function build_throws_exception_if_issuer_contains_replacement(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectErrorMessageMatches('~^Replace \{yourOktaDomain\} with your Okta domain~');
        $verifier = new JwtVerifierBuilder();
        $verifier->setIssuer('https://{yourOktaDomain}/');
        $verifier->build();
    }

    /** @test */
    public function build_throws_exception_if_client_id_not_set(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectErrorMessageMatches('~^Your client ID is missing~');
        $verifier = new JwtVerifierBuilder();
        $verifier->setIssuer('https://issuer/');
        $verifier->build();
    }

    /** @test */
    public function build_throws_exception_if_client_id_contains_replacement(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectErrorMessageMatches('~^Replace \{clientId\} with the client ID of your Application~');
        $verifier = new JwtVerifierBuilder();
        $verifier->setIssuer('https://issuer/');
        $verifier->setClientId('this is my {clientId}');
        $verifier->build();
    }

    /** @test */
    public function building_the_verifier_returns_instance_of_jwt_verifier(): void
    {
        $builder = new JwtVerifierBuilder();
        $verifier = $builder
            ->setIssuer('https://my.issuer.com')
            ->setClientId("abc123")
            ->build();

        self::assertInstanceOf(
            JwtVerifier::class,
            $verifier,
            'The verifier builder is not returning an instance of JwtVerifier'
        );
    }

    /** @test */
    public function discovery_defaults_to_oauth_when_building(): void
    {
        $builder = new JwtVerifierBuilder();
        $verifier = $builder
            ->setIssuer('https://my.issuer.com')
            ->setClientId("abc123")
            ->build();

        self::assertInstanceOf(
            Oauth::class,
            $verifier->getServer()->getDiscovery(),
            'The builder is not defaulting to oauth2 discovery'
        );
    }
}
