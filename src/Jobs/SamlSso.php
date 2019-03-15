<?php

namespace CodeGreenCreative\SamlIdp\Jobs;

use LightSaml\ClaimTypes;
use LightSaml\Binding\BindingFactory;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\Model\Assertion\Conditions;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Assertion\AuthnContext;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Model\Assertion\AuthnStatement;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\AudienceRestriction;
use LightSaml\Model\Assertion\SubjectConfirmation;
use CodeGreenCreative\SamlIdp\Contracts\SamlContract;
use LightSaml\Model\Assertion\SubjectConfirmationData;

class SamlSso implements SamlContract
{
    use Dispatchable, PerformsSingleSignOn;

    /**
     * [__construct description]
     */
    public function __construct()
    {
        $this->init();
    }

    /**
     * Execute the job.
     *
     * @return void
     */
    public function handle()
    {
        $deserializationContext = new DeserializationContext;
        $deserializationContext->getDocument()->loadXML(gzinflate(base64_decode(request('SAMLRequest'))));

        $this->authn_request = new AuthnRequest;
        $this->authn_request->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

        $this->destination = config(sprintf(
            'samlidp.sp.%s.destination',
            $this->getServiceProvider($this->authn_request)
        )) . '?idp=' . config('app.url');

        return $this->response();
    }

    public function response()
    {
        $this->response = (new Response)->setIssuer(new Issuer($this->issuer))
            ->setStatus(new Status(new StatusCode('urn:oasis:names:tc:SAML:2.0:status:Success')))
            ->addAssertion($assertion = new Assertion)
            ->setID(Helper::generateID())
            ->setIssueInstant(new \DateTime)
            ->setDestination($this->destination)
            ->setInResponseTo($this->authn_request->getId());

        $assertion
            ->setId(Helper::generateID())
            ->setIssueInstant(new \DateTime)
            ->setIssuer(new Issuer($this->issuer))
            ->setSignature(new SignatureWriter($this->certificate, $this->private_key))
            ->setSubject(
                (new Subject)
                    ->setNameID((new NameID(auth()->user()->email, SamlConstants::NAME_ID_FORMAT_EMAIL)))
                    ->addSubjectConfirmation(
                        (new SubjectConfirmation)
                            ->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new SubjectConfirmationData())
                                    ->setInResponseTo($this->authn_request->getId())
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    ->setRecipient($this->authn_request->getAssertionConsumerServiceURL())
                            )
                    )
            )
            ->setConditions(
                (new Conditions)
                    ->setNotBefore(new \DateTime)
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                        new AudienceRestriction([$this->authn_request->getIssuer()->getValue()])
                    )
            )
            ->addItem(
                (new AuthnStatement)
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex(Helper::generateID())
                    ->setAuthnContext(
                        (new AuthnContext)
                            ->setAuthnContextClassRef(SamlConstants::NAME_ID_FORMAT_UNSPECIFIED)
                    )
            )
            ->addItem(
                (new AttributeStatement)
                    ->addAttribute(new Attribute(ClaimTypes::EMAIL_ADDRESS, auth()->user()->email))
            );
         return $this->send(SamlConstants::BINDING_SAML2_HTTP_POST);
    }

    /**
     * [sendSamlRequest description]
     *
     * @param  Request $request [description]
     * @param  User    $user    [description]
     * @return [type]           [description]
     */
    public function send($binding_type)
    {
        $bindingFactory = new BindingFactory;
        $postBinding = $bindingFactory->create($binding_type);
        $messageContext = new MessageContext;
        $messageContext->setMessage($this->response)->asResponse();
        $message = $messageContext->getMessage();
        $message->setRelayState(request('RelayState'));
        $httpResponse = $postBinding->send($messageContext);

        return $httpResponse->getContent();
    }
}
