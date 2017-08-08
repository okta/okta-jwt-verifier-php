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

use Http\Client\Common\PluginClient;
use Http\Client\HttpClient;
use Http\Discovery\HttpClientDiscovery;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Discovery\UriFactoryDiscovery;
use Okta\JwtVerifier\Adaptors\Adaptor;
use Okta\JwtVerifier\Discovery\DiscoveryMethod;

class JwtVerifier
{
    /**
     * @var string
     */
    protected $issuer;

    /**
     * @var DiscoveryMethod
     */
    protected $discovery;

    public function __construct(
        string $issuer,
        DiscoveryMethod $discovery,
        Adaptor $adaptor,
        Request $request = null
    ) {
        $this->issuer = $issuer;
        $this->discovery = $discovery;
        $this->adaptor = $adaptor;
        $request = $request ?: new Request;
        $this->metaData = json_decode($request->setUrl($this->issuer.$this->discovery->getWellKnown())->get()
            ->getBody());
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function getDiscovery()
    {
        return $this->discovery;
    }

    public function getMetaData()
    {
        return $this->metaData;
    }

    public function verify($jwt)
    {
        $keys = $this->adaptor->getKeys($this->metaData->jwks_uri);

        return $this->adaptor->decode($jwt, $keys);
    }
}
