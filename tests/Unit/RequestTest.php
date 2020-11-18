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

use Http\Mock\Client;
use Okta\JwtVerifier\Request;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ResponseInterface;
use Test\BaseTestCase;

class RequestTest extends BaseTestCase
{
    /**
     * @var MockObject|ResponseInterface
     */
    protected $response;

    public function setUp(): void
    {
        parent::setUp();

        $this->response = $this->createMock(ResponseInterface::class);
    }

    /** @test */
    public function makes_request_to_correct_location(): void
    {
        $this->response->method('getStatusCode')->willReturn(200);

        $httpClient = new Client;
        $httpClient->addResponse($this->response);

        $request = new Request($httpClient);

        $response = $request->setUrl('http://example.com')->get();
        $requests = $httpClient->getRequests();

        self::assertInstanceOf(
            ResponseInterface::class,
            $response,
            'Response was not an instance of ResponseInterface.'
        );

        self::assertEquals(
            'http://example.com',
            $requests[0]->getUri(),
            'Did not make a request to the set URL'
        );

    }

    /** @test */
    public function makes_request_to_correct_location_with_query(): void
    {
        $this->response->method('getStatusCode')->willReturn(200);

        $httpClient = new Client;
        $httpClient->addResponse($this->response);

        $request = new Request($httpClient);

        $request
            ->setUrl('http://example.com')
            ->withQuery('some','query')
            ->withQuery('and','another')
            ->get();

        $requests = $httpClient->getRequests();

        self::assertEquals(
            'http://example.com?some=query&and=another',
            $requests[0]->getUri(),
            'Did not make a request to the set URL'
        );

    }
}
