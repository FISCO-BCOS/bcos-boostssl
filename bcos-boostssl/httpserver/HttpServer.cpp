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
 * @file HttpHttpServer.h
 * @author: octopus
 * @date 2021-07-08
 */

#include <bcos-boostssl/httpserver/HttpServer.h>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::http;

// start http server
void HttpServer::start()
{
    if (m_acceptor && m_acceptor->is_open())
    {
        HTTP_SERVER(INFO) << LOG_BADGE("startListen") << LOG_DESC("http server is running");
        return;
    }

    HTTP_SERVER(INFO) << LOG_BADGE("startListen") << LOG_KV("listenIP", m_listenIP)
                      << LOG_KV("listenPort", m_listenPort);

    auto address = boost::asio::ip::make_address(m_listenIP);
    auto endpoint = boost::asio::ip::tcp::endpoint{address, m_listenPort};

    boost::beast::error_code ec;
    m_acceptor->open(endpoint.protocol(), ec);
    if (ec)
    {
        HTTP_SERVER(ERROR) << LOG_BADGE("open") << LOG_KV("error", ec)
                           << LOG_KV("message", ec.message());
        BOOST_THROW_EXCEPTION(std::runtime_error("acceptor open failed"));
    }

    // allow address reuse
    m_acceptor->set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        HTTP_SERVER(ERROR) << LOG_BADGE("set_option") << LOG_KV("error", ec)
                           << LOG_KV("message", ec.message());

        BOOST_THROW_EXCEPTION(std::runtime_error("acceptor set_option failed"));
    }

    m_acceptor->bind(endpoint, ec);
    if (ec)
    {
        HTTP_SERVER(ERROR) << LOG_BADGE("bind") << LOG_KV("error", ec)
                           << LOG_KV("message", ec.message());
        BOOST_THROW_EXCEPTION(std::runtime_error("acceptor bind failed"));
    }

    m_acceptor->listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        HTTP_SERVER(ERROR) << LOG_BADGE("listen") << LOG_KV("error", ec)
                           << LOG_KV("message", ec.message());
        BOOST_THROW_EXCEPTION(std::runtime_error("acceptor listen failed"));
    }

    // start accept
    doAccept();

    HTTP_SERVER(INFO) << LOG_BADGE("startListen") << LOG_KV("ip", endpoint.address().to_string())
                      << LOG_KV("port", endpoint.port());
}

void HttpServer::stop()
{
    if (m_acceptor && m_acceptor->is_open())
    {
        m_acceptor->close();
    }

    if (m_ioc && !m_ioc->stopped())
    {
        m_ioc->stop();
    }

    HTTP_SERVER(INFO) << LOG_BADGE("stop") << LOG_DESC("http server");
}

void HttpServer::doAccept()
{
    // The new connection gets its own strand
    m_acceptor->async_accept(boost::asio::make_strand(*m_ioc),
        boost::beast::bind_front_handler(&HttpServer::onAccept, shared_from_this()));
}

void HttpServer::onAccept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
{
    if (ec)
    {
        HTTP_SERVER(ERROR) << LOG_BADGE("accept") << LOG_KV("error", ec)
                           << LOG_KV("message", ec.message());
    }
    else
    {
        HTTP_SERVER(INFO) << LOG_BADGE("accept")
                          << LOG_KV("local_endpoint", socket.local_endpoint())
                          << LOG_KV("remote_endpoint", socket.remote_endpoint());

        auto httpSession = m_httpSessionFactory->createSession(std::move(socket));
        httpSession->setRequestHandler(m_httpReqHandler);
        httpSession->setWsUpgradeHandler(m_wsUpgradeHandler);
        httpSession->run();
    }

    // Accept another connection
    doAccept();
}

/**
 * @brief: create http server
 * @param _listenIP: listen ip
 * @param _listenPort: listen port
 * @param _threadCount: thread count
 * @param _ioc: io_context
 * @param _ctx: ssl context
 * @return HttpServer::Ptr:
 */
HttpServer::Ptr HttpServerFactory::buildHttpServer(const std::string& _listenIP,
    uint16_t _listenPort, std::shared_ptr<boost::asio::io_context> _ioc,
    std::shared_ptr<boost::asio::ssl::context> _ctx)
{
    // create httpserver and launch a listening port
    auto server = std::make_shared<HttpServer>(_listenIP, _listenPort);
    auto acceptor =
        std::make_shared<boost::asio::ip::tcp::acceptor>(boost::asio::make_strand(*_ioc));

    auto sessionFactory = std::make_shared<HttpSessionFactory>();

    server->setIoc(_ioc);
    server->setAcceptor(acceptor);
    server->setHttpSessionFactory(sessionFactory);
    server->setCtx(_ctx);

    HTTP_SERVER(INFO) << LOG_BADGE("buildHttpServer") << LOG_KV("listenIP", _listenIP)
                      << LOG_KV("listenPort", _listenPort);
    return server;
}
