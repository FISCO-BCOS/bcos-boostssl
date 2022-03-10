/*
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @file SslCertInfo.cpp
 * @author: lucasli
 * @date 2022-03-07
 */

#include <bcos-boostssl/context/SslCertInfo.h>
#include <bcos-boostssl/context/Common.h>
#include <bcos-utilities/DataConvertUtility.h>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/algorithm/string/classification.hpp>

using namespace bcos::boostssl::context;

std::function<bool(bool, boost::asio::ssl::verify_context&)> SslCertInfo::newVerifyCallback(
    std::shared_ptr<std::string> nodeIDOut)
{
    auto sslCertInfo = std::weak_ptr<SslCertInfo>(shared_from_this());
    return [sslCertInfo, nodeIDOut](bool preverified, boost::asio::ssl::verify_context& ctx) {
        auto sslCertInfoPtr = sslCertInfo.lock();
        if (!sslCertInfoPtr)
        {
            return false;
        }

        try
        {
            /// return early when the certificate is invalid
            if (!preverified)
            {
                return false;
            }
            /// get the object points to certificate
            X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            if (!cert)
            {
                SSLCERT_LOG(ERROR) << LOG_DESC("Get cert failed");
                return preverified;
            }

            if (!sslCertInfoPtr->sslContextPubHandler()(cert, *nodeIDOut.get()))
            {
                return preverified;
            }

            int crit = 0;
            BASIC_CONSTRAINTS* basic =
                (BASIC_CONSTRAINTS*)X509_get_ext_d2i(cert, NID_basic_constraints, &crit, NULL);
            if (!basic)
            {
                SSLCERT_LOG(ERROR) << LOG_DESC("Get ca basic failed");
                return preverified;
            }

            /// ignore ca
            if (basic->ca)
            {
                // ca or agency certificate
                SSLCERT_LOG(TRACE) << LOG_DESC("Ignore CA certificate");
                BASIC_CONSTRAINTS_free(basic);
                return preverified;
            }

            BASIC_CONSTRAINTS_free(basic);
            // if (!hostPtr->sslContextPubHandler()(cert, *nodeIDOut.get())) {
            //   return preverified;
            // }

            /// append cert-name and issuer name after node ID
            /// get subject name
            const char* certName = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            /// get issuer name
            const char* issuerName = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
            /// format: {nodeID}#{issuer-name}#{cert-name}
            nodeIDOut->append("#");
            nodeIDOut->append(issuerName);
            nodeIDOut->append("#");
            nodeIDOut->append(certName);
            OPENSSL_free((void*)certName);
            OPENSSL_free((void*)issuerName);

            return preverified;
        }
        catch (std::exception& e)
        {
            SSLCERT_LOG(ERROR) << LOG_DESC("Cert verify failed") << boost::diagnostic_information(e);
            return preverified;
        }
    };
}

void SslCertInfo::initSSLContextPubHexHandler()
{
    auto handler = [](X509* x509, std::string& _pubHex) -> bool {
    ASN1_BIT_STRING* pubKey =
    X509_get0_pubkey_bitstr(x509);  // csc->current_cert is an X509 struct
    if (pubKey == NULL)
    {
        return false;
    }

    auto hex = bcos::toHexString(pubKey->data, pubKey->data + pubKey->length, "");
    _pubHex = *hex.get();

    SSLCERT_LOG(INFO) << LOG_DESC("[NEW]SSLContext pubHex: " + _pubHex);
    return true;
    };

    m_sslContextPubHandler = handler;
}