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
 * @file SslCertInfo.h
 * @author: lucasli
 * @date 2022-03-07
 */
#pragma once
#include <openssl/x509.h>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <functional>

namespace bcos
{
namespace boostssl
{
namespace context
{
class SslCertInfo : public std::enable_shared_from_this<SslCertInfo>
{
public:
	using Ptr = std::shared_ptr<SslCertInfo>;
    using ConstPtr = std::shared_ptr<const SslCertInfo>;
	
	SslCertInfo()
	{
		initSSLContextPubHexHandler();
	}
	
	void initSSLContextPubHexHandler();

    std::function<bool(X509* x509, std::string& pubHex)> sslContextPubHandler()
    {
        return m_sslContextPubHandler;
    }

    std::function<bool(bool, boost::asio::ssl::verify_context&)> newVerifyCallback(
        std::shared_ptr<std::string> nodeIDOut);
        
private:
    std::function<bool(X509* cert, std::string& pubHex)> m_sslContextPubHandler;
};

}  // namespace context
}  // namespace boostssl
}  // namespace bcos