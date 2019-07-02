<!--
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
-->
# eidas/PSD2 Authentication Node

This EIDAS/PSD2 authentication node allows you to offer to your users a way to authenticate in AM using their EIDAS/PSD2 certificates.

It's a collector node, meaning that it would collect the certificate, read it and populate the shared state and user session
with the information contained in the certificate.

It can be used on its own if wishes, and in that case, the application id referred in the certificate will be used as username.


This node relies on having the certificate received via the request header. This choice of implementation is link to the fact
that AM is rarely directly exposed and the SSL termination done at the gateway level.
You would need to make sure that the gateway is initiating the MTLS and populating the verified certificates into the 
request header, before passing the request to AM.

Those headers can be customised in the node configuration, to fit your convention. It also accepts JWK format.


You can enforce the certificate to be a PSD2 one and also enforce which type of certificates you are expected.

For example, you can enforce a TPP to authenticate using his QSEAL certificate in order to manually on-board.

[forgerock_platform]: https://www.forgerock.com/platform/  
