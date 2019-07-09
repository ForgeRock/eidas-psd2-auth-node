/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2019 ForgeRock AS.
 */


package com.forgerock.eidasAuthNode;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

import javax.inject.Inject;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.eidas.EidasCertType;
import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.exception.NoSuchRDNInField;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.cert.utils.CertificateUtils;
import com.nimbusds.jose.jwk.JWK;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

/**
 * A node that collect EIDAS and PSD2 certificate attribute and put them into the shared state and user session
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = EidasAuthNode.Config.class)
public class EidasAuthNode extends SingleOutcomeNode {


    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    private static String CLIENT_CERTIFICATE_HEADER_NAME = "x-client-cert";
    private static String CLIENT_CERTIFICATE_PEM_HEADER_NAME = "x-client-pem-cert";

    public static final String APP_ID = "app_id";
    public static final String ORG_ID = "org_id";
    public static final String PSD2_ROLES = "psd2_roles";


    private final Logger logger = LoggerFactory.getLogger(EidasAuthNode.class);
    private final Config config;
    private final Realm realm;

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100)
        default String clientCertificateInPemFormatHeader() {
            return CLIENT_CERTIFICATE_PEM_HEADER_NAME;
        }

        @Attribute(order = 200)
        default String clientCertificateInJWKFormatHeader() {
            return CLIENT_CERTIFICATE_HEADER_NAME;
        }

        @Attribute(order = 300)
        default boolean requirePSD2Cert() {
            return false;
        }

        @Attribute(order = 400)
        default boolean requireSpecificEIDASTypes() {
            return false;
        }
        @Attribute(order = 500)
        default List<EidasCertType> requestedEIDASTypes() {
            return Arrays.asList(EidasCertType.values());
        }
    }

    @Inject
    public EidasAuthNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        //Read certificate from request header
        Optional<String> psd2CertPem = getFirstValueHeader(context.request, config.clientCertificateInPemFormatHeader());
        Optional<String> psd2JWKSerialised = getFirstValueHeader(context.request, config.clientCertificateInJWKFormatHeader());

        Action.ActionBuilder actionBuilder = goToNext();
        JsonValue shareState = context.sharedState.copy();

        Optional<X509Certificate> hasCert = getX509CertificateFromRequest(psd2CertPem, psd2JWKSerialised, actionBuilder, shareState);

        if (!hasCert.isPresent()) {
            logger.debug("No certificate received");
            return goToNext().build();
        }
        X509Certificate clientCertificate = hasCert.get();
        if (logger.isDebugEnabled()) {
            serialiseCertificate(clientCertificate).ifPresent(c -> logger.debug("Certificate in pem is " + c));
        }

        try {
            //Load it as a PSD2 cert
            Psd2CertInfo psd2CertInfo = new Psd2CertInfo(Arrays.asList(clientCertificate));
            logger.debug("PSD2 certificate info loaded from the certificate: {}", psd2CertInfo);

            if (!psd2CertInfo.isPsd2Cert()) {
                logger.debug("Certificate is not a PSD2 certificate");
                if (config.requirePSD2Cert()) {
                    logger.debug("PSD2 certificate required -> auth node error");
                    String serialiseCertificate = serialiseCertificate(clientCertificate).orElse("");
                    throw new NodeProcessException("Certificate is not a PSD2 certificate. Cert:" + serialiseCertificate);
                }
            }

            if (config.requireSpecificEIDASTypes()) {
                logger.debug("Require specific EIDAS types enabled");
                if (!psd2CertInfo.getEidasCertType().isPresent()) {
                    throw new NodeProcessException("No EIDAS certificate type found");
                }
                logger.debug("EIDAS certificate type {}", psd2CertInfo.getEidasCertType().get());
                if (config.requestedEIDASTypes().contains(psd2CertInfo.getEidasCertType().get())) {
                    logger.debug("This EIDAS type is in our whitelist");
                } else {
                    throw new NodeProcessException("EIDAS type " + psd2CertInfo.getEidasCertType().get() + " not accepted. Please use one of the type: " + config.requestedEIDASTypes());
                }
            }

            //Define the username if not set yet
            if (!shareState.contains(USERNAME)) {
                logger.debug("No username defined, use the application id {} from the certificate as identifier", psd2CertInfo.getApplicationId());
                shareState.put(USERNAME, psd2CertInfo.getApplicationId());
            } else {
                logger.debug("Username already populated: {}", shareState.get(USERNAME));
            }

            //Map certificate attributes to user session and shared state
            mapCertificateAttributeToSessionAndSharedState(actionBuilder, shareState, psd2CertInfo);

            return actionBuilder.replaceSharedState(shareState).build();
        } catch (InvalidPsd2EidasCertificate | NoSuchRDNInField | CertificateEncodingException | InvalidEidasCertType e) {
            String cert = serialiseCertificate(clientCertificate).orElse("");
            logger.warn("Error loading certificate '{}' ", cert, e);
            throw new NodeProcessException("Certificate loading failed for " + cert);
        }
    }

    private void mapCertificateAttributeToSessionAndSharedState(Action.ActionBuilder actionBuilder, JsonValue shareState, Psd2CertInfo psd2CertInfo) throws NoSuchRDNInField, CertificateEncodingException, InvalidPsd2EidasCertificate {
        //Map application ID
        shareState.put(APP_ID, psd2CertInfo.getApplicationId());
        actionBuilder.putSessionProperty(APP_ID, psd2CertInfo.getApplicationId());
        logger.debug("PSD2 application ID behind certificate: {}", psd2CertInfo.getApplicationId());

        //Map Organisation ID
        psd2CertInfo.getOrganizationId().ifPresent(organisationId -> {
                    actionBuilder.putSessionProperty(ORG_ID, organisationId);
                    shareState.put(ORG_ID, organisationId);
                    logger.debug("PSD2 organisation ID behind certificate: {}", organisationId);
                });

        //Map PSD2 roles
        Optional<Psd2QcStatement> psd2QcStatementOpt = psd2CertInfo.getPsd2QCStatement();
        if (psd2QcStatementOpt.isPresent()) {
            Psd2QcStatement psd2QcStatement = psd2QcStatementOpt.get();
            RolesOfPsp roles = psd2QcStatement.getRoles();
            shareState.put(PSD2_ROLES, roles.getRolesOfPsp().stream().map(r -> r.getRole()).collect(Collectors.toList()));
            actionBuilder.putSessionProperty(PSD2_ROLES, roles.getRolesOfPsp().stream().map(r -> r.getRole().name()).collect(Collectors.joining(",")));
            logger.debug("PSD2 roles behind certificate: {}", roles.getRolesOfPsp().stream().map(r -> r.getRole()).collect(Collectors.toList()));
        }
    }

    private Optional<X509Certificate> getX509CertificateFromRequest(Optional<String> psd2CertPem, Optional<String> psd2JWKSerialised, Action.ActionBuilder actionBuilder, JsonValue shareState) {

        logger.debug("Priority is to load the certificate from the pem header {}. If empty, try the JWK format from header {}",
                config.clientCertificateInPemFormatHeader(),
                config.clientCertificateInJWKFormatHeader()
                );

        logger.debug("Trying Pem format");
        if (psd2CertPem.isPresent()) {
            logger.debug("Pem certificate received: {}", psd2CertPem.get());
            shareState.put(config.clientCertificateInPemFormatHeader(), psd2CertPem.get());
            actionBuilder.putSessionProperty(config.clientCertificateInPemFormatHeader(), psd2CertPem.get());
            return parseCertificate(psd2CertPem.get());
        } else {
            logger.debug("No Pem format");
        }

        logger.debug("Trying JWK format");
        if (psd2JWKSerialised.isPresent()) {
            try {
                logger.debug("JWK received: {}", psd2JWKSerialised.get());
                shareState.put(config.clientCertificateInJWKFormatHeader(), psd2JWKSerialised.get());
                actionBuilder.putSessionProperty(config.clientCertificateInJWKFormatHeader(), psd2JWKSerialised.get());

                JWK psd2CertAsJWK = JWK.parse(psd2JWKSerialised.get());
                if (psd2CertAsJWK.getX509CertChain() == null || psd2CertAsJWK.getX509CertChain().isEmpty()) {
                    logger.debug("No certificate in JWK {}", psd2JWKSerialised);
                    return Optional.empty();
                }
                return Optional.of(CertificateUtils.decodeCertificate(psd2CertAsJWK.getX509CertChain().get(0).decode()));
            } catch (CertificateException | ParseException e) {
                logger.warn("Error loading PSD2 JWK '{}' ", psd2JWKSerialised, e);
                return Optional.empty();
            }
        } else {
            logger.debug("No JWK format");
        }
        logger.debug("Need to receive from the gateway either the pem or the JWK version of the PSD2 certificate");
        return Optional.empty();
    }


    private Optional<X509Certificate> parseCertificate(String certStr) {
        //before decoding we need to get rod off the prefix and suffix
        logger.debug("Client certificate as PEM format: \n {}", certStr);

        try {

            byte [] decoded = Base64.getDecoder()
                    .decode(
                            certStr
                                    .replaceAll("\n", "")
                                    .replaceAll(BEGIN_CERT, "")
                                    .replaceAll(END_CERT, ""));
            return Optional.of((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded)));
        } catch (CertificateException e) {
            logger.error("Can't initialise certificate factory", e);
        }
        return Optional.empty();
    }

    private Optional<String> getFirstValueHeader(ExternalRequestContext requestContext, String headerName) {
        List<String> headerValues = requestContext.headers.get(headerName);
        if (headerValues == null || headerValues.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(headerValues.get(0));
    }

    private Optional<String> serialiseCertificate(X509Certificate certificate) {
        PrintStream ps = null;
        ByteArrayOutputStream bs = null;
        try {

            bs = new ByteArrayOutputStream();
            ps = new PrintStream(bs);

            ps.println(BEGIN_CERT);
            ps.println(Base64.getEncoder().encode(certificate.getEncoded()));
            ps.println(END_CERT);
            return Optional.of(new String(bs.toByteArray()));
        } catch (CertificateEncodingException e) {
            logger.error("Couldn't encode certificate", e);
            return Optional.empty();
        } finally {
            if (ps != null) {
                ps.close();
            }
            if (bs != null) {
                try {
                    bs.close();
                } catch (IOException e) {
                    logger.error("Couldn't close properly ByteArrayOutputStream", e);
                }
            }
        }
    }
}
