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
 * @file ContextBuilder.cpp
 * @author: octopus
 * @date 2021-06-14
 */

#include <bcos-boostssl/context/Common.h>
#include <bcos-boostssl/context/ContextBuilder.h>
#include <bcos-boostssl/context/ContextConfig.h>
#include <bcos-utilities/BoostLog.h>
#include <boost/exception/diagnostic_information.hpp>
#include <exception>
#include <iostream>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::context;

// static const std::string DEFAULT_CONFIG = "./boostssl.ini";

std::shared_ptr<std::string> ContextBuilder::readFileContent(boost::filesystem::path const& _file)
{
    std::shared_ptr<std::string> content = std::make_shared<std::string>();
    boost::filesystem::ifstream fileStream(_file, std::ifstream::binary);
    if (!fileStream)
    {
        return content;
    }
    fileStream.seekg(0, fileStream.end);
    auto length = fileStream.tellg();
    if (length == 0)
    {
        return content;
    }
    fileStream.seekg(0, fileStream.beg);
    content->resize(length);
    fileStream.read((char*)content->data(), length);
    return content;
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSslContext(
    const std::string& _configPath)
{
    auto config = std::make_shared<ContextConfig>();
    config->initConfig(_configPath);
    return buildSslContext(*config);
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSslContext(
    const ContextConfig& _contextConfig)
{
    if (_contextConfig.isCertPath())
    {
        if (_contextConfig.sslType() != "sm_ssl")
        {
            return buildSslContext(_contextConfig.certConfig());
        }
        return buildSmSslContext(_contextConfig.smCertConfig());
    }
    else
    {
        if (_contextConfig.sslType() != "sm_ssl")
        {
            return buildSslContextByCertContent(_contextConfig.certConfig());
        }
        return buildSmSslContextByCertContent(_contextConfig.smCertConfig());
    }
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSslContext(
    const ContextConfig::CertConfig& _certConfig)
{
    auto nodekeyContent = readFileContent(boost::filesystem::path(_certConfig.nodeKey));
    auto nodeCertContent = readFileContent(boost::filesystem::path(_certConfig.nodeCert));
    auto caCertContent = readFileContent(boost::filesystem::path(_certConfig.caCert));

    ContextConfig::CertConfig certContentConfig;
    certContentConfig.nodeKey = *nodekeyContent.get();
    certContentConfig.nodeCert = *nodeCertContent.get();
    certContentConfig.caCert = *caCertContent.get();

    return buildSslContextByCertContent(certContentConfig);
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSmSslContext(
    const ContextConfig::SMCertConfig& _smCertConfig)
{
    ContextConfig::SMCertConfig smCertContentConfig;

    auto nodeKeyContent =
        readFileContent(boost::filesystem::path(_smCertConfig.nodeKey));  // sm_ssl.key content
    auto nodeCertContent = readFileContent(boost::filesystem::path(_smCertConfig.nodeCert));
    auto enNodeKeyContent =
        readFileContent(boost::filesystem::path(_smCertConfig.enNodeKey));  // sm_enssl.key content
    auto enNodeCertContent = readFileContent(boost::filesystem::path(_smCertConfig.enNodeCert));
    auto caCertContent = readFileContent(boost::filesystem::path(_smCertConfig.caCert));

    smCertContentConfig.nodeKey = *nodeKeyContent.get();
    smCertContentConfig.nodeCert = *nodeCertContent.get();
    smCertContentConfig.enNodeKey = *enNodeKeyContent.get();
    smCertContentConfig.enNodeCert = *enNodeCertContent.get();
    smCertContentConfig.caCert = *caCertContent.get();

    return buildSmSslContextByCertContent(smCertContentConfig);
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSslContextByCertContent(
    const ContextConfig::CertConfig& _certConfig)
{
    std::shared_ptr<boost::asio::ssl::context> sslContext =
        std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12);

    auto nodeKey = std::make_shared<std::string>(_certConfig.nodeKey);
    // decrypt data in nodekey content
    // if dataDecryptHandler is not nullptr that means content need to be decrypted
    if (m_dataDecryptHandler != nullptr)
    {
        nodeKey = m_dataDecryptHandler(*nodeKey.get());
    }

    sslContext->use_private_key(boost::asio::const_buffer(nodeKey->data(), nodeKey->size()),
        boost::asio::ssl::context::file_format::pem);
    sslContext->use_certificate_chain(
        boost::asio::const_buffer(_certConfig.nodeCert.data(), _certConfig.nodeCert.size()));

    sslContext->add_certificate_authority(
        boost::asio::const_buffer(_certConfig.caCert.data(), _certConfig.caCert.size()));

    std::string caPath;
    if (!caPath.empty())
    {
        sslContext->add_verify_path(caPath);
    }

    sslContext->set_verify_mode(boost::asio::ssl::context_base::verify_peer |
                                boost::asio::ssl::verify_fail_if_no_peer_cert);

    return sslContext;
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSmSslContextByCertContent(
    const ContextConfig::SMCertConfig& _smCertConfig)
{
    std::shared_ptr<boost::asio::ssl::context> sslContext =
        std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12);

    sslContext->set_verify_mode(boost::asio::ssl::context_base::verify_none);

    auto nodeKey = std::make_shared<std::string>(_smCertConfig.nodeKey);
    auto enNodeKey = std::make_shared<std::string>(_smCertConfig.enNodeKey);
    // decrypt data in nodekey and ennodekey file
    // if dataDecryptHandler is not nullptr that means content need to be decrypted
    if (m_dataDecryptHandler != nullptr)
    {
        nodeKey = m_dataDecryptHandler(*nodeKey.get());
        enNodeKey = m_dataDecryptHandler(*enNodeKey.get());
    }

    sslContext->use_private_key(boost::asio::const_buffer(nodeKey->data(), nodeKey->size()),
        boost::asio::ssl::context::file_format::pem);  // node.key

    int ret = 0;

    ret = SSL_CTX_use_enc_certificate(
        sslContext->native_handle(), toX509(_smCertConfig.enNodeCert.c_str()));
    if (ret <= 0)  // en_node.crt
    {
        CONTEXT_LOG(WARNING) << LOG_BADGE("buildSslContext")
                             << LOG_DESC("SSL_CTX_use_enc_certificate") << LOG_KV("error", ret);
        BOOST_THROW_EXCEPTION(std::runtime_error(
            "SSL_CTX_use_enc_certificate failed, error: " + std::to_string(ret)));
    }

    ret = SSL_CTX_use_enc_PrivateKey(sslContext->native_handle(), toEvpPkey(enNodeKey->c_str()));
    if (ret <= 0)  // en_node.key
    {
        CONTEXT_LOG(WARNING) << LOG_BADGE("buildSslContext")
                             << LOG_DESC("SSL_CTX_use_enc_PrivateKey") << LOG_KV("error", ret);
        BOOST_THROW_EXCEPTION(
            std::runtime_error("SSL_CTX_use_enc_PrivateKey, error: " + std::to_string(ret)));
    }

    sslContext->use_certificate_chain(boost::asio::const_buffer(
        _smCertConfig.nodeCert.data(), _smCertConfig.nodeCert.size()));  // node.crt
    sslContext->add_certificate_authority(boost::asio::const_buffer(
        _smCertConfig.caCert.data(), _smCertConfig.caCert.size()));  // ca.crt

    std::string caPath;
    if (!caPath.empty())
    {
        sslContext->add_verify_path(caPath);
    }

    sslContext->set_verify_mode(boost::asio::ssl::context_base::verify_peer |
                                boost::asio::ssl::verify_fail_if_no_peer_cert);

    return sslContext;
}