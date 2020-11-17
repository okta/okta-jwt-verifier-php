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

use DomainException;
use Okta\JwtVerifier\Adaptor\Adaptor;
use Okta\JwtVerifier\Adaptor\AutoDiscover;
use Okta\JwtVerifier\Server\Server;

class JwtVerifier
{
    public const VALIDATE_NONCE = 'nonce';
    public const VALIDATE_AUDIENCE = 'audience';
    public const VALIDATE_CLIENT_ID = 'client_id';

    /**
     * @var Server
     */
    protected $server;

    /**
     * @var array
     */
    protected $claimsToValidate;

    /**
     * @var Adaptor
     */
    protected $adaptor;

    public function __construct(
        Server $server,
        ?Adaptor $adaptor = null,
        array $claimsToValidate = []
    ) {
        $this->server = $server;
        $this->adaptor = $adaptor ?: AutoDiscover::getAdaptor();
        $this->claimsToValidate = $claimsToValidate;
    }

    public function getServer(): Server
    {
        return $this->server;
    }

    public function getAdaptor(): Adaptor
    {
        return $this->adaptor;
    }

    public function verify($jwt): Jwt
    {
        $keys = $this->adaptor->parseKeySet($this->server->getKeys());

        $decoded = $this->adaptor->decode($jwt, $keys);

        $this->validateClaims($decoded->getClaims());

        return $decoded;
    }

    private function validateClaims(array $claims): void
    {
        $this->validateNonce($claims);
        $this->validateAudience($claims);
        $this->validateClientId($claims);
    }

    private function validateNonce($claims): void
    {
        if (isset($claims['nonce'])
            && $this->claimsToValidate[self::VALIDATE_NONCE] !== null
            && $claims['nonce'] !== $this->claimsToValidate[self::VALIDATE_NONCE]
        ) {
            throw new DomainException(
                'Nonce does not match what is expected. ' .
                'Make sure to provide the nonce with `setNonce()` from the JwtVerifierBuilder.'
            );
        }
    }

    private function validateAudience($claims): void
    {
        if (isset($claims['aud'])
            && $this->claimsToValidate[self::VALIDATE_AUDIENCE] !== null
            && $claims['aud'] !== $this->claimsToValidate[self::VALIDATE_AUDIENCE]
        ) {
            throw new DomainException(
                'Audience does not match what is expected. ' .
                'Make sure to provide the audience with `setAudience()` from the JwtVerifierBuilder.'
            );
        }
    }

    private function validateClientId($claims): void
    {
        if (isset($claims['cid'])
            && $this->claimsToValidate[self::VALIDATE_CLIENT_ID] !== null
            && $claims['cid'] !== $this->claimsToValidate[self::VALIDATE_CLIENT_ID]
        ) {
            throw new DomainException(
                'ClientId does not match what is expected. ' .
                'Make sure to provide the client id with `setClientId()` from the JwtVerifierBuilder.'
            );
        }
    }
}
