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
 * @file WsFactory.cpp
 * @author: octopus
 * @date 2021-09-29
 */
#include <bcos-boostssl/context/ContextBuilder.h>
#include <bcos-boostssl/websocket/Common.h>
#include <bcos-boostssl/websocket/WsConfig.h>
#include <bcos-boostssl/websocket/WsConnector.h>
#include <bcos-boostssl/websocket/WsInitializer.h>
#include <bcos-boostssl/websocket/WsMessage.h>
#include <bcos-boostssl/websocket/WsService.h>
#include <bcos-boostssl/websocket/WsSession.h>
#include <bcos-framework/libutilities/Log.h>
#include <cstddef>
#include <memory>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::ws;
using namespace bcos::boostssl::http;

void WsInitializer::initWsService(WsService::Ptr _wsService)
{
    std::shared_ptr<bcos::boostssl::ws::WsConfig> _config = m_config;
    auto messageFactory = m_messageFactory;
    if (messageFactory == nullptr)
    {
        messageFactory = std::make_shared<bcos::boostssl::ws::WsMessageFactory>();
    }

    auto wsServiceWeakPtr = std::weak_ptr<WsService>(_wsService);
    auto ioc = std::make_shared<boost::asio::io_context>();
    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(*ioc);
    auto connector = std::make_shared<WsConnector>(resolver, ioc);

    auto threadPool = std::make_shared<bcos::ThreadPool>(
        "t_ws", _config->threadPoolSize() > 0 ? _config->threadPoolSize() : 4);

    std::shared_ptr<boost::asio::ssl::context> ctx = nullptr;
    if (!m_config->boostsslConfig().empty())
    {
        auto contextBuilder = std::make_shared<bcos::boostssl::context::ContextBuilder>();
        ctx = contextBuilder->buildSslContext(m_config->boostsslConfig());
    }

    if (_config->asServer())
    {
        if (!WsConfig::validIP(_config->listenIP()))
        {
            BOOST_THROW_EXCEPTION(
                InvalidParameter()
                << errinfo_comment("initWsService: invalid listen ip, ip=" + _config->listenIP()));
        }

        if (!WsConfig::validPort(_config->listenPort()))
        {
            BOOST_THROW_EXCEPTION(
                InvalidParameter() << errinfo_comment("initWsService: invalid listen port, port=" +
                                                      std::to_string(_config->listenPort())));
        }

        auto httpServerFactory = std::make_shared<HttpServerFactory>();
        auto httpServer = httpServerFactory->buildHttpServer(
            _config->listenIP(), _config->listenPort(), ioc, ctx);
        httpServer->setWsUpgradeHandler(
            [wsServiceWeakPtr](boost::asio::ip::tcp::socket&& _stream, HttpRequest&& _req) {
                auto service = wsServiceWeakPtr.lock();
                if (service)
                {
                    auto session = service->newSession(
                        std::make_shared<boost::beast::websocket::stream<boost::beast::tcp_stream>>(
                            std::move(_stream)));
                    // accept websocket handshake
                    session->doAccept(_req);
                }
            });

        _wsService->setHttpServer(httpServer);
    }

    if (_config->asClient())
    {
        auto connectedPeers = _config->connectedPeers();
        if (connectedPeers)
        {
            for (auto const& peer : *connectedPeers)
            {
                if (!WsConfig::validIP(peer.host))
                {
                    BOOST_THROW_EXCEPTION(
                        InvalidParameter() << errinfo_comment(
                            "initWsService: invalid connect host, host=" + peer.host));
                }

                if (!WsConfig::validPort(peer.port))
                {
                    BOOST_THROW_EXCEPTION(InvalidParameter() << errinfo_comment(
                                              "initWsService: invalid connect port, port=" +
                                              std::to_string(peer.port)));
                }
            }
        }
        else
        {
            WEBSOCKET_INITIALIZER(WARNING)
                << LOG_BADGE("initWsService") << LOG_DESC("there has no connected server config");
        }
    }

    _wsService->setConfig(_config);
    _wsService->setThreadPool(threadPool);
    _wsService->setIoc(ioc);
    _wsService->setConnector(connector);
    _wsService->setMessageFactory(messageFactory);

    WEBSOCKET_INITIALIZER(INFO) << LOG_BADGE("initWsService")
                                << LOG_DESC("initializer for websocket service")
                                << LOG_KV("boostssl config", _config->boostsslConfig())
                                << LOG_KV("thread pool size", _config->threadPoolSize())
                                << LOG_KV("server", _config->asServer())
                                << LOG_KV("listenIP", _config->listenIP())
                                << LOG_KV("listenPort", _config->listenPort())
                                << LOG_KV("client", _config->asClient())
                                << LOG_KV("connected peers", _config->connectedPeers()->size());
}