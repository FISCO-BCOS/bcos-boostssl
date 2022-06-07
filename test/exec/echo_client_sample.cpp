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
 * @file echo_client_sample.cpp
 * @author: octopus
 * @date 2021-10-31
 */

#include "bcos-boostssl/websocket/WsInitializer.h"
#include <bcos-boostssl/websocket/Common.h>
#include <bcos-boostssl/websocket/WsService.h>
#include <bcos-utilities/BoostLog.h>
#include <bcos-utilities/Common.h>
#include <bcos-utilities/ThreadPool.h>
#include <string>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::ws;
using namespace bcos::boostssl::http;
using namespace bcos::boostssl::context;


#define TEST_LOG(LEVEL, module_name) BCOS_LOG(LEVEL) << LOG_BADGE(module_name) << "[WS][SERVICE]"

void usage()
{
    std::cerr << "Usage: echo-client-sample <peerIp> <peerPort> <ssl> <dataSize>\n"
              << "Example:\n"
              << "    ./echo-client-sample 127.0.0.1 20200 true 2\n"
              << "    ./echo-client-sample 127.0.0.1 20200 false 2\n";
    std::exit(0);
}

void sendMessage(std::shared_ptr<MessageFace> _msg, std::shared_ptr<WsService> _wsService)
{
    int i = 0;
    while (true)
    {
        auto seq = _wsService->messageFactory()->newSeq();
        _msg->setSeq(seq);
        auto startT = utcTime();
        auto msgSize = _msg->payload()->size();
        _wsService->asyncSendMessage(_msg, Options(-1),
            [msgSize, startT](Error ::Ptr _error, std::shared_ptr<boostssl::MessageFace>,
                std::shared_ptr<WsSession> _session) {
                (void)_session;
                if (_error && _error->errorCode() != 0)
                {
                    TEST_LOG(WARNING, "TEST_CLIENT_MODULE")
                        << LOG_BADGE(" [Main] ===>>>> ") << LOG_DESC("callback response error")
                        << LOG_KV("errorCode", _error->errorCode())
                        << LOG_KV("errorMessage", _error->errorMessage());
                    return;
                }
                BCOS_LOG(INFO) << LOG_DESC("receiveResponse, timecost:") << (utcTime() - startT)
                               << LOG_KV("msgSize", msgSize);
            });
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        i++;
    }
}

int main(int argc, char** argv)
{
    if (argc < 5)
    {
        usage();
    }

    std::string host = argv[1];
    uint16_t port = atoi(argv[2]);

    std::string disableSsl = "true";
    uint32_t sizeNum = 1;
    // uint16_t interval = 10;

    if (argc > 3)
    {
        disableSsl = argv[3];
    }
    std::string test_module_name = "testClient";
    TEST_LOG(INFO, test_module_name)
        << LOG_DESC("echo-client-sample") << LOG_KV("ip", host) << LOG_KV("port", port)
        << LOG_KV("disableSsl", disableSsl) << LOG_KV("datasize", sizeNum);

    auto config = std::make_shared<WsConfig>();
    config->setModel(WsModel::Client);

    NodeIPEndpoint endpoint = NodeIPEndpoint(host, port);

    auto peers = std::make_shared<EndPoints>();
    peers->insert(endpoint);
    config->setConnectPeers(peers);

    config->setThreadPoolSize(8);
    config->setMaxMsgSize(100 * 1024 * 1024);
    config->setDisableSsl(0 == disableSsl.compare("true"));
    if (!config->disableSsl())
    {
        auto contextConfig = std::make_shared<ContextConfig>();
        contextConfig->initConfig("./boostssl.ini");
        config->setContextConfig(contextConfig);
    }
    config->setModuleName("TEST_CLIENT");

    auto wsService = std::make_shared<ws::WsService>(config->moduleName());
    auto wsInitializer = std::make_shared<WsInitializer>();

    auto sessionFactory = std::make_shared<WsSessionFactory>();
    wsInitializer->setSessionFactory(sessionFactory);

    wsInitializer->setConfig(config);
    wsInitializer->initWsService(wsService);

    wsService->start();

    ThreadPool::Ptr threadPool = std::make_shared<ThreadPool>("send", 16);
    std::srand(utcTime());
    for (int i = 0; i < 1000; i++)
    {
        // construct message
        auto msg =
            std::dynamic_pointer_cast<WsMessage>(wsService->messageFactory()->buildMessage());
        msg->setPacketType(999);
        int64_t payloadSize = 0;
        uint32_t a = std::rand();
        uint32_t b = std::rand();
        if (i % 2)
        {
            payloadSize = (((uint32_t)a << 16) | b) % (1024 * 1024);
        }
        else
        {
            payloadSize = (((uint32_t)a << 16) | b) % (20 * 1024);
        }
        std::string randStr(payloadSize, 'a');
        msg->setPayload(std::make_shared<bytes>(randStr.begin(), randStr.end()));
        threadPool->enqueue([msg, wsService]() { sendMessage(msg, wsService); });
    }
    return EXIT_SUCCESS;
}
