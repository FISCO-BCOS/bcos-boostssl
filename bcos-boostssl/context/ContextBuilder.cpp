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
#include <boost/exception/diagnostic_information.hpp>
#include <exception>
#include <iostream>

using namespace boostssl;
using namespace boostssl::context;

// default config
static const std::string DEFAULT_CONFIG = "./boostssl.ini";

std::shared_ptr<std::string>
ContextBuilder::readFileContent(boost::filesystem::path const &_file) {
  std::shared_ptr<std::string> content = std::make_shared<std::string>();
  boost::filesystem::ifstream fileStream(_file, std::ifstream::binary);
  if (!fileStream) {
    return content;
  }
  fileStream.seekg(0, fileStream.end);
  auto length = fileStream.tellg();
  if (length == 0) {
    return content;
  }
  fileStream.seekg(0, fileStream.beg);
  content->resize(length);
  fileStream.read(content->data(), length);
  return content;
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSslContext() {
  return buildSslContext(DEFAULT_CONFIG);
}

std::shared_ptr<boost::asio::ssl::context>
ContextBuilder::buildSslContext(const std::string &_configPath) {
  auto config = std::make_shared<ContextConfig>();
  config->initConfig(_configPath);
  if (config->sslType() == "tassl_sm") {
    return buildSslContext(config->smCertConfig());
  }
  return buildSslContext(config->certConfig());
}

std::shared_ptr<boost::asio::ssl::context>
ContextBuilder::buildSslContext(const ContextConfig::CertConfig &_certConfig) {
  std::shared_ptr<boost::asio::ssl::context> sslContext =
      std::make_shared<boost::asio::ssl::context>(
          boost::asio::ssl::context::tlsv12);

  auto keyContent = readFileContent(
      boost::filesystem::path(_certConfig.nodeKey)); // node.key content
  if (!keyContent || keyContent->empty()) {
    BOOST_THROW_EXCEPTION(
        std::runtime_error("unable read node key: " + _certConfig.nodeKey));
  }

  boost::asio::const_buffer keyBuffer(keyContent->data(), keyContent->size());
  sslContext->use_private_key(keyBuffer,
                              boost::asio::ssl::context::file_format::pem);

  // node.crt
  sslContext->use_certificate_chain_file(_certConfig.nodeCert);

  auto caCertContent =
      readFileContent(boost::filesystem::path(_certConfig.caCert)); // ca.crt
  if (!caCertContent || caCertContent->empty()) {
    BOOST_THROW_EXCEPTION(
        std::runtime_error("unable read ca: " + _certConfig.caCert));
  }
  sslContext->add_certificate_authority(
      boost::asio::const_buffer(caCertContent->data(), caCertContent->size()));

  std::string caPath;
  if (!caPath.empty()) {
    sslContext->add_verify_path(caPath);
  }

  sslContext->set_verify_mode(boost::asio::ssl::context_base::verify_peer |
                              boost::asio::ssl::verify_fail_if_no_peer_cert);

  return sslContext;
}

std::shared_ptr<boost::asio::ssl::context> ContextBuilder::buildSslContext(
    const ContextConfig::SMCertConfig &_smCertConfig) {
  std::shared_ptr<boost::asio::ssl::context> sslContext =
      std::make_shared<boost::asio::ssl::context>(
          boost::asio::ssl::context::tlsv12);

  sslContext->set_verify_mode(boost::asio::ssl::context_base::verify_none);

  auto keyContent = readFileContent(
      boost::filesystem::path(_smCertConfig.nodeKey)); // node.key content

  boost::asio::const_buffer keyBuffer(keyContent->data(), keyContent->size());
  sslContext->use_private_key(keyBuffer,
                              boost::asio::ssl::context::file_format::pem);

  SSL_CTX_use_enc_certificate_file(sslContext->native_handle(),
                                   _smCertConfig.enNodeCert.c_str(),
                                   SSL_FILETYPE_PEM);
  if (SSL_CTX_use_enc_PrivateKey_file(sslContext->native_handle(),
                                      _smCertConfig.enNodeKey.c_str(),
                                      SSL_FILETYPE_PEM) <= 0) {
    BOOST_THROW_EXCEPTION(
        std::runtime_error("SSL_CTX_use_enc_PrivateKey_file, en nodekey: " +
                           _smCertConfig.enNodeKey));
  }

  sslContext->use_certificate_chain_file(_smCertConfig.nodeCert);

  auto caContent = readFileContent(
      boost::filesystem::path(_smCertConfig.caCert)); // node.key content

  sslContext->add_certificate_authority(
      boost::asio::const_buffer(caContent->data(), caContent->size()));

  std::string caPath;
  if (!caPath.empty()) {
    sslContext->add_verify_path(caPath);
  }

  sslContext->set_verify_mode(boost::asio::ssl::context_base::verify_peer |
                              boost::asio::ssl::verify_fail_if_no_peer_cert);

  return sslContext;
}