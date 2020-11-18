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

use InvalidArgumentException;
use Okta\JwtVerifier\Server\DefaultServer;
use Okta\JwtVerifier\Server\Discovery\Discovery;
use Okta\JwtVerifier\Adaptor\Adaptor;

class JwtVerifierBuilder
{
    /**
     * @var string|null
     */
    protected $issuer;

    /**
     * @var Discovery|null
     */
    protected $discovery;

    /**
     * @var Request|null
     */
    protected $request;

    /**
     * @var Adaptor|null
     */
    protected $adaptor;

    /**
     * @var string|null
     */
    protected $audience;

    /**
     * @var string|null
     */
    protected $clientId;

    /**
     * @var string|null
     */
    protected $nonce;

    public function __construct(Request $request = null)
    {
        $this->request = $request;
    }

    /**
     * Sets the issuer URI.
     *
     * @param string $issuer The issuer URI
     * @return JwtVerifierBuilder
     */
    public function setIssuer(string $issuer): self
    {
        $this->issuer = rtrim($issuer, "/");

        return $this;
    }

    /**
     * Set the Discovery class. This class should be an instance of DiscoveryMethod.
     *
     * @param Discovery $discoveryMethod The DiscoveryMethod instance.
     * @return JwtVerifierBuilder
     */
    public function setDiscovery(Discovery $discoveryMethod): self
    {
        $this->discovery = $discoveryMethod;

        return $this;
    }

    /**
     * Set the Adaptor class. This class should be an interface of Adaptor.
     *
     * @param Adaptor $adaptor The adaptor of the JWT library you are using.
     * @return JwtVerifierBuilder
     */
    public function setAdaptor(Adaptor $adaptor): self
    {
        $this->adaptor = $adaptor;

        return $this;
    }

    public function setAudience(string $audience): self
    {
        $this->audience = $audience;

        return $this;
    }

    public function setClientId(string $clientId): self
    {
        $this->clientId = $clientId;

        return $this;
    }

    public function setNonce(string $nonce): self
    {
        $this->nonce = $nonce;

        return $this;
    }

    /**
     * Build and return the JwtVerifier.
     *
     * @throws InvalidArgumentException
     * @return JwtVerifier
     */
    public function build(): JwtVerifier
    {
        $this->validateIssuer($this->issuer);
        $this->validateClientId($this->clientId);

        return new JwtVerifier(
            new DefaultServer(
                $this->issuer,
                $this->discovery,
                $this->request
            ),
            $this->adaptor,
            [
                'nonce' => $this->nonce,
                'audience' => $this->audience,
                'clientId' => $this->clientId
            ]
        );
    }

    /**
     * Validate the issuer
     *
     * @param string|null $issuer
     * @throws InvalidArgumentException
     * @return void
     */
    private function validateIssuer(?string $issuer): void {
        if (null === $issuer || "" === $issuer) {
            throw new InvalidArgumentException("Your Issuer is missing. You can find your issuer from your authorization server settings in the Okta Developer Console. Find out more information aobut Authorization Servers at https://developer.okta.com/docs/guides/customize-authz-server/overview/");
        }

        if (strpos($issuer, "https://") === false) {
            throw new InvalidArgumentException("Your Issuer must start with https. Current value: {$issuer}. You can copy your issuer from your authorization server settings in the Okta Developer Console. Find out more information aobut Authorization Servers at https://developer.okta.com/docs/guides/customize-authz-server/overview/");
        }

        if (strpos($issuer, "{yourOktaDomain}") !== false) {
            throw new InvalidArgumentException("Replace {yourOktaDomain} with your Okta domain. You can copy your domain from the Okta Developer Console. Follow these instructions to find it: https://bit.ly/finding-okta-domain");
        }
    }

    /**
     * Validate the client id
     *
     * @param string|null $cid
     * @throws InvalidArgumentException
     * @return void
     */
    private function validateClientId(?string $cid): void {
        if (null === $cid || "" === $cid) {
            throw new InvalidArgumentException("Your client ID is missing. You can copy it from the Okta Developer Console in the details for the Application you created. Follow these instructions to find it: https://bit.ly/finding-okta-app-credentials");
        }

        if (strpos($cid, "{clientId}") !== false) {
            throw new InvalidArgumentException("Replace {clientId} with the client ID of your Application. You can copy it from the Okta Developer Console in the details for the Application you created. Follow these instructions to find it: https://bit.ly/finding-okta-app-credentials");
        }
    }
}
