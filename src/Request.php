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
use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;

class Request
{
    /**
     * @var PluginClient
     */
    protected $httpClient;

    /**
     * @var UriFactoryInterface
     */
    protected $uriFactory;

    /**
     * @var RequestFactoryInterface
     */
    protected $requestFactory;

    /**
     * The UriInterface of the request to be made.
     *
     * @var UriInterface
     */
    protected $url;

    /**
     * The set of query parameters to send with request.
     *
     * @var array
     */
    protected $query = [];

    public function __construct(
        HttpClient $httpClient = null,
        UriFactoryInterface $uriFactory = null,
        RequestFactoryInterface $messageFactory = null
    ) {
        $this->httpClient = new PluginClient(
            $httpClient ?: HttpClientDiscovery::find()
        );
        $this->uriFactory = $uriFactory ?: Psr17FactoryDiscovery::findUrlFactory();
        $this->requestFactory = $messageFactory ?: Psr17FactoryDiscovery::findRequestFactory();
    }

    public function setUrl($url): Request
    {
        $this->url = $this->uriFactory->createUri($url);
        return $this;
    }

    public function withQuery($key, $value = null): Request
    {
        $this->query[$key] = $value;

        return $this;
    }

    public function get(): ResponseInterface
    {
        return $this->request('GET');
    }

    protected function request($method): ResponseInterface
    {
        if (!empty($this->query)) {
            $this->url = $this->url->withQuery(http_build_query($this->query));
        }

        $request = $this->requestFactory->createRequest($method, $this->url);
        $request->withHeader('Accept', 'application/json');

        return $this->httpClient->sendRequest($request);

    }
}
