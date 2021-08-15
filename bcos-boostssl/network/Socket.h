/*
 * @CopyRight:
 * bcos-boostssl is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * bcos-boostssl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with bcos-boostssl.  If not, see <http://www.gnu.org/licenses/>
 * (c) 2021-2023 fisco-dev contributors.
 */
/**
 * @file Socket.h
 * @author octopus
 * @date 2021-06-07
 */

#pragma once
#include <bcos-boostssl/network/Common.h>
#include <bcos-boostssl/network/SocketFace.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/filesystem.hpp>

namespace boostssl
{
namespace net
{
class Socket : public SocketFace, public std::enable_shared_from_this<Socket>
{
public:
    Socket(
        ba::io_service& _ioService, ba::ssl::context& _sslContext, NodeIPEndpoint _nodeIPEndpoint)
      : m_nodeIPEndpoint(_nodeIPEndpoint)
    {
        try
        {
            m_sslSocket =
                std::make_shared<ba::ssl::stream<bi::tcp::socket>>(_ioService, _sslContext);
        }
        catch (const std::exception& _e)
        {
            SESSION_LOG(ERROR) << "ERROR: " << boost::diagnostic_information(_e);
        }
    }
    ~Socket() { close(); }

    virtual bool isConnected() const override { return m_sslSocket->lowest_layer().is_open(); }

    virtual void close() override
    {
        try
        {
            boost::system::error_code ec;
            m_sslSocket->lowest_layer().shutdown(bi::tcp::socket::shutdown_both, ec);
            if (m_sslSocket->lowest_layer().is_open())
                m_sslSocket->lowest_layer().close();
        }
        catch (...)
        {
        }
    }

    virtual bi::tcp::endpoint remoteEndpoint(
        boost::system::error_code ec = boost::system::error_code()) override
    {
        return m_sslSocket->lowest_layer().remote_endpoint(ec);
    }

    virtual bi::tcp::endpoint localEndpoint(
        boost::system::error_code ec = boost::system::error_code()) override
    {
        return m_sslSocket->lowest_layer().local_endpoint(ec);
    }

    virtual bi::tcp::socket& ref() override { return m_sslSocket->next_layer(); }
    virtual ba::ssl::stream<bi::tcp::socket>& sslref() override { return *m_sslSocket; }

    virtual const NodeIPEndpoint& nodeIPEndpoint() const override { return m_nodeIPEndpoint; }
    virtual void setNodeIPEndpoint(NodeIPEndpoint _nodeIPEndpoint) override
    {
        m_nodeIPEndpoint = _nodeIPEndpoint;
    }

protected:
    NodeIPEndpoint m_nodeIPEndpoint;
    std::shared_ptr<ba::ssl::stream<bi::tcp::socket>> m_sslSocket;
};

}  // namespace net
}  // namespace boostssl
