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
#include <bcos-boostssl/websocket/WsFactory.h>
#include <bcos-boostssl/websocket/WsMessage.h>
#include <bcos-boostssl/websocket/WsService.h>
#include <bcos-boostssl/websocket/WsSession.h>
#include <memory>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::ws;
using namespace bcos::boostssl::http;

std::shared_ptr<WsService> WsFactory::buildWsService()
{
    // TODO: check if m_config valid
    auto ioc = std::make_shared<boost::asio::io_context>();
    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(*ioc);
    auto connector = std::make_shared<WsConnector>(resolver, ioc);
    auto messageFactory = std::make_shared<WsMessageFactory>();
    auto threadPool = std::make_shared<bcos::ThreadPool>("t_ws", m_config->threadPoolSize());
    auto wsService = std::make_shared<WsService>();
    auto wsServiceWeakPtr = std::weak_ptr<WsService>(wsService);

    if (m_config->asServer())
    {
        // TODO: ssl impl
        /*
        auto contextBuilder = std::make_shared<bcos::boostssl::context::ContextBuilder>();
        std::shared_ptr<boost::asio::ssl::context> ctx =
            contextBuilder->buildSslContext("conf/boostssl.ini");
        */
        auto httpServerFactory = std::make_shared<HttpServerFactory>();
        auto httpServer =
            httpServerFactory->buildHttpServer(m_config->listenIP(), m_config->listenPort(), ioc);
        wsService->setHttpServer(httpServer);

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
    }

    if (m_config->asClient())
    {
    }

    wsService->setConfig(m_config);
    wsService->setThreadPool(threadPool);
    wsService->setIoc(ioc);
    wsService->setConnector(connector);
    wsService->setMessageFactory(messageFactory);

    WEBSOCKET_FACTORY(INFO) << LOG_DESC("construct websocket service object")
                            << LOG_KV("server", m_config->asServer())
                            << LOG_KV("listenIP", m_config->listenIP())
                            << LOG_KV("listenPort", m_config->listenPort())
                            << LOG_KV("client", m_config->asClient())
                            << LOG_KV("connected peers count", m_config->connectedPeers()->size())
                            << LOG_KV("thread pool size", m_config->threadPoolSize());

    return wsService;
}
