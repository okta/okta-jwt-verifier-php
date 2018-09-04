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

use PHPUnit\Framework\TestCase;

class BaseTestCase extends TestCase
{
    /**
     * @return \GuzzleHttp\ClientInterface|PHPUnit_Framework_MockObject_MockObject
     */
    protected function getClientMock()
    {
        return $this->getMock('GuzzleHttp\ClientInterface', [], [], '', false);
    }

    /**
     * @return PHPUnit_Framework_MockObject_MockObject|\Psr\Http\Message\ResponseInterface
     */
    protected function getResponseMock()
    {
        return $this->getMock('Psr\Http\Message\ResponseInterface');
    }
}
