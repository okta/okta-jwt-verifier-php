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

namespace Okta\JwtVerifier;

use Carbon\Carbon;
use Carbon\CarbonInterface;

class Jwt
{
    /**
     * @var string
     */
    private $token;

    /**
     * @var array
     */
    private $claims;

    public function __construct(string $jwt, array $claims)
    {
        $this->token = $jwt;
        $this->claims = $claims;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * @param bool $carbonInstance
     * @return CarbonInterface|int
     */
    public function getExpirationTime($carbonInstance = true)
    {
        if (!isset($this->claims['exp'])) {
            throw new \DomainException('JWT does not contain "exp" claim');
        }

        $ts = $this->claims['exp'];

        if ($carbonInstance && class_exists(Carbon::class)) {
            return Carbon::createFromTimestampUTC($ts);
        }

        return $ts;
    }

    /**
     * @param bool $carbonInstance
     * @return CarbonInterface|int
     */
    public function getIssuedAt($carbonInstance = true)
    {
        if (!isset($this->claims['iat'])) {
            throw new \DomainException('JWT does not contain "iat" claim');
        }

        $ts = $this->claims['iat'];

        if ($carbonInstance && class_exists(Carbon::class)) {
            return Carbon::createFromTimestampUTC($ts);
        }

        return $ts;
    }
}
