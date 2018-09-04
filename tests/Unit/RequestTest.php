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

use Okta\JwtVerifier\Request;

class RequestTest extends BaseTestCase
{
    /** @test */
    public function makes_request_to_correct_location()
    {
        $response = $this->getResponseMock();
        $response
            ->method('getStatusCode')
            ->willReturn(200);

        $httpClient = $this->getClientMock();
        $httpClient
            ->method('send')
            ->with($this->isInstanceOf(\Psr\Http\Message\RequestInterface::class))
            ->willReturnCallback(function (\Psr\Http\Message\RequestInterface $request) use ($response) {
                $this->assertEquals(
                    'http://example.com',
                    (string) $request->getUri(),
                    'Did not make a request to the set URL'
                );

                return $response;
            });

        $request = new Request($httpClient);

        $response = $request->setUrl('http://example.com')->get();

        $this->assertInstanceOf(
            \Psr\Http\Message\ResponseInterface::class,
            $response,
            'Response was not an instance of ResponseInterface.'
        );
    }

    /** @test */
    public function makes_request_to_correct_location_with_query()
    {
        $response = $this->getResponseMock();
        $response
            ->method('getStatusCode')
            ->willReturn(200);

        $httpClient = $this->getClientMock();
        $httpClient
            ->method('send')
            ->with($this->isInstanceOf(\Psr\Http\Message\RequestInterface::class))
            ->willReturnCallback(function (\Psr\Http\Message\RequestInterface $request) use ($response) {
                $this->assertEquals(
                    'http://example.com?some=query&and=another',
                    (string) $request->getUri(),
                    'Did not make a request to the set URL'
                );

                return $response;
            });

        $request = new Request($httpClient);

        $response = $request
            ->setUrl('http://example.com')
            ->withQuery('some','query')
            ->withQuery('and','another')
            ->get();

        $this->assertInstanceOf(
            \Psr\Http\Message\ResponseInterface::class,
            $response,
            'Response was not an instance of ResponseInterface.'
        );
    }
}
