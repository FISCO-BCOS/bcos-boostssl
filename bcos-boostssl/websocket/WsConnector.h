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
 *  m_limitations under the License.
 *
 * @file WsConnector.h
 * @author: octopus
 * @date 2021-08-23
 */
#pragma once
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <functional>
#include <mutex>
#include <set>
#include <string>

namespace bcos
{
namespace boostssl
{
namespace ws
{
class WsConnector
{
public:
    using Ptr = WsConnector;
    WsConnector(std::shared_ptr<boost::asio::ip::tcp::resolver> _resolver,
        std::shared_ptr<boost::asio::io_context> _ioc)
      : m_resolver(_resolver), m_ioc(_ioc)
    {}

public:
    /**
     * @brief:
     * @param _host: the remote server host, support ipv4, ipv6, domain name
     * @param _port: the remote server port
     * @param _callback:
     * @return void:
     */
    void connectToWsServer(const std::string& _host, uint16_t _port,
        std::function<void(boost::beast::error_code _ec,
            std::shared_ptr<boost::beast::websocket::stream<boost::beast::tcp_stream>>)>
            _callback);

public:
    void erasePendingConns(const std::string& _nodeIPEndpoint)
    {
        std::lock_guard<std::mutex> l(x_pendingConns);
        if (m_pendingConns.count(_nodeIPEndpoint))
            m_pendingConns.erase(_nodeIPEndpoint);
    }

    void insertPendingConns(const std::string& _nodeIPEndpoint)
    {
        std::lock_guard<std::mutex> l(x_pendingConns);
        if (!m_pendingConns.count(_nodeIPEndpoint))
            m_pendingConns.insert(_nodeIPEndpoint);
    }

public:
    void setResolver(std::shared_ptr<boost::asio::ip::tcp::resolver> _resolver)
    {
        m_resolver = _resolver;
    }
    std::shared_ptr<boost::asio::ip::tcp::resolver> resolver() const { return m_resolver; }

    void setIoc(std::shared_ptr<boost::asio::io_context> _ioc) { m_ioc = _ioc; }
    std::shared_ptr<boost::asio::io_context> ioc() const { return m_ioc; }

private:
    std::shared_ptr<boost::asio::ip::tcp::resolver> m_resolver;
    std::shared_ptr<boost::asio::io_context> m_ioc;

    mutable std::mutex x_pendingConns;
    std::set<std::string> m_pendingConns;
};
}  // namespace ws
}  // namespace boostssl
}  // namespace bcos
