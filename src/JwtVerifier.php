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

class JwtVerifier
{
    protected $issuer;
    protected $discovery;
    protected $wellKnown;

    public function __construct(
        string $issuer,
        string $discovery
    )
    {
        $this->issuer = $issuer;
        $this->discovery = $discovery;
        $this->wellKnown = $this->buildWellKnownEndpoint();
    }

    private function buildWellKnownEndpoint()
    {
        switch ($this->discovery) {
            case 'oidc':
                return $this->issuer . '/.well-known/openid-configuration';
            case 'oauth2':
            case 'oauth':
                return $this->issuer . '/.well-known/oauth-authorization-server';
            default:
                throw new \InvalidArgumentException('Please provide a discovery method.');
        }
    }

    public function getWellKnown()
    {
        return $this->wellKnown;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function getDiscovery()
    {
        return $this->discovery;
    }
}
