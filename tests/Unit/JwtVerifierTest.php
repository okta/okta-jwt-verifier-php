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

use Okta\JwtVerifier\JwtVerifier;
use PHPUnit\Framework\TestCase;

class JwtVerifierTest extends TestCase
{
    /** @test */
    public function it_throws_exception_if_discovery_is_not_valid()
    {
        $this->expectException(\InvalidArgumentException::class);
        new JwtVerifier('https://my.issuer.com', 'something');
    }

    /** @test */
    public function it_creates_oauth_well_known_correctly()
    {
        $verifier = new JwtVerifier('https://my.issuer.com', 'oauth');

        $this->assertEquals(
            'https://my.issuer.com/.well-known/oauth-authorization-server',
            $verifier->getWellKnown(),
            'Well known endpoint was not generated correctly.'
        );

        $verifier = new JwtVerifier('https://my.issuer.com', 'oauth2');

        $this->assertEquals(
            'https://my.issuer.com/.well-known/oauth-authorization-server',
            $verifier->getWellKnown(),
            'Well known endpoint was not generated correctly.'
        );
    }

    /** @test */
    public function it_creates_oidc_well_known_correctly()
    {
        $verifier = new JwtVerifier('https://my.issuer.com', 'oidc');

        $this->assertEquals(
            'https://my.issuer.com/.well-known/openid-configuration',
            $verifier->getWellKnown(),
            'Well known endpoint was not generated correctly.'
        );

    }

    /** @test */
    public function can_get_issuer_off_object()
    {
        $verifier = new JwtVerifier('https://my.issuer.com', 'oidc');
        $this->assertEquals(
            'https://my.issuer.com',
            $verifier->getIssuer(),
            'Does not return issuer correctly'
        );
    }

    /** @test */
    public function can_get_discovery_off_object()
    {
        $verifier = new JwtVerifier('https://my.issuer.com', 'oidc');
        $this->assertEquals(
            'oidc',
            $verifier->getDiscovery(),
            'Does not return discovery correctly'
        );
    }

}
