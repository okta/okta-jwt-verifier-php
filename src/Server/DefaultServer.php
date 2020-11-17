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

namespace Okta\JwtVerifier\Server;

use Okta\JwtVerifier\Server\Discovery\Discovery;
use Okta\JwtVerifier\Server\Discovery\Oauth;
use Okta\JwtVerifier\Request;
use RuntimeException;

class DefaultServer implements Server
{
    /**
     * @var string
     */
    protected $issuer;

    /**
     * @var Discovery
     */
    protected $discovery;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var string
     */
    protected $wellKnown;

    /**
     * @var object | null
     */
    protected $metaData;

    /**
     * @var object | null
     */
    protected $keys;

    public function __construct(
        string $issuer,
        ?Discovery $discovery = null,
        ?Request $request = null
    ) {
        $this->issuer = $issuer;
        $this->discovery = $discovery ?: new Oauth;
        $this->request = $request ?: new Request;
        $this->wellKnown = $this->issuer . $this->discovery->getWellKnown();
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getDiscovery(): Discovery
    {
        return $this->discovery;
    }

    public function getMetaData(): object
    {
        if ($this->metaData === null) {
            $this->metaData = $this->loadMetaData($this->request, $this->wellKnown);
        }

        return $this->metaData;
    }

    private function loadMetaData(Request $request, string $wellKnown): object
    {
        $metaDataJson = $request->setUrl($wellKnown)->get()->getBody()->getContents();

        if (!is_string($metaDataJson)) {
            throw new RuntimeException(
                "We made a call to {$wellKnown} endpoint, but did not receive json."
            );
        }

        $metaData = json_decode($metaDataJson);

        if (json_last_error() !== JSON_ERROR_NONE
            || !is_object($metaData)
            || ! $metaData instanceof \stdClass
        ) {
            throw new RuntimeException(
                "We made a call to {$wellKnown} endpoint, but did not receive a valid json object."
            );
        }

        return $metaData;
    }

    public function getKeys()
    {
        if ($this->keys === null) {
            $metaData = $this->getMetaData();

            if (!isset($metaData->jwks_uri) || $metaData->jwks_uri === null) {
                throw new RuntimeException(
                    "Could not access a valid JWKS_URI from the metadata. " .
                    "We made a call to {$this->wellKnown} endpoint, but jwks_uri was null. " .
                    "Please make sure you are using a custom authorization server for the jwt verifier."
                );
            }

            $this->keys = $this->request->setUrl($metaData->jwks_uri)->get()->getBody()->getContents();
        }

        return $this->keys;
    }
}
