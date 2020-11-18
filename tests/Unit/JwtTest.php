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

use Carbon\CarbonInterface;
use DomainException;
use Okta\JwtVerifier\Jwt;
use Test\BaseTestCase;

class JwtTest extends BaseTestCase
{
    /** @test */
    public function can_get_token_from_constructor(): void
    {
        $jwt = new Jwt('my-token', []);

        self::assertSame(
            'my-token',
            $jwt->getToken(),
            'Does not return token correctly'
        );
    }

    /** @test */
    public function can_get_claims_from_constructor(): void
    {
        $jwt = new Jwt('', ['my-claim' => 'content']);

        self::assertSame(
            ['my-claim' => 'content'],
            $jwt->getClaims(),
            'Does not return claims correctly'
        );
    }

    /** @test */
    public function can_get_raw_expiration_time(): void
    {
        $jwt = new Jwt('', [
            'exp' => 4102444800
        ]);

        self::assertSame(
            4102444800,
            $jwt->getExpirationTime(false),
            'Does not return expiration timestamp correctly'
        );
    }

    /** @test */
    public function can_get_carbon_expiration_time(): void
    {
        $jwt = new Jwt('', [
            'exp' => 4102444800
        ]);

        self::assertInstanceOf(
            CarbonInterface::class,
            $jwt->getExpirationTime()
        );

        self::assertSame(
            '2100-01-01 00:00:00',
            $jwt->getExpirationTime()->format(CarbonInterface::DEFAULT_TO_STRING_FORMAT),
            'Does not return expiration timestamp correctly'
        );
    }

    /** @test */
    public function throws_exception_when_exp_claim_not_present(): void
    {
        $jwt = new Jwt('', []);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('JWT does not contain "exp" claim');

        $jwt->getExpirationTime();
    }

    /** @test */
    public function can_get_raw_issued_at_time(): void
    {
        $jwt = new Jwt('', [
            'iat' => 1577836800
        ]);

        self::assertSame(
            1577836800,
            $jwt->getIssuedAt(false),
            'Does not return expiration timestamp correctly'
        );
    }

    /** @test */
    public function can_get_carbon_issued_at_time(): void
    {
        $jwt = new Jwt('', [
            'exp' => 1577836800
        ]);

        self::assertInstanceOf(
            CarbonInterface::class,
            $jwt->getExpirationTime()
        );

        self::assertSame(
            '2020-01-01 00:00:00',
            $jwt->getExpirationTime()->format(CarbonInterface::DEFAULT_TO_STRING_FORMAT),
            'Does not return expiration timestamp correctly'
        );
    }

    /** @test */
    public function throws_exception_when_iat_claim_not_present(): void
    {
        $jwt = new Jwt('', []);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('JWT does not contain "iat" claim');

        $jwt->getIssuedAt();
    }
}
