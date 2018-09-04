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

class Jwt
{
    /**
     * @var string
     */
    protected $jwt;

    /**
     * @var array
     */
    protected $claims;

    /**
     * @param string $jwt
     * @param array $claims
     */
    public function __construct($jwt, array $claims)
    {
        $this->jwt = $jwt;
        $this->claims = $claims;
    }

    /**
     * @return string
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * @return array
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * @return int
     */
    public function getExpirationTime()
    {
        $ts = $this->toJson()->exp;

        return $ts;
    }

    /**
     * @return int
     */
    public function getIssuedAt()
    {
        $ts = $this->toJson()->iat;

        return $ts;
    }

    /**
     * @return object
     */
    public function toJson()
    {
        if(is_resource($this->claims)) {
            throw new \InvalidArgumentException('Could not convert to JSON');
        }

        return json_decode(json_encode($this->claims));
    }
}
