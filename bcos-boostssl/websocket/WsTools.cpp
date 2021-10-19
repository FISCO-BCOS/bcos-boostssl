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
 * @file WsTools.cpp
 * @author: octopus
 * @date 2021-10-19
 */
#include <bcos-boostssl/websocket/Common.h>
#include <bcos-boostssl/websocket/WsConfig.h>
#include <bcos-boostssl/websocket/WsTools.h>
#include <boost/algorithm/string.hpp>

using namespace bcos;
using namespace bcos::boostssl;
using namespace bcos::boostssl::ws;

bool WsTools::stringToEndPoint(const std::string& _peer, EndPoint& _endpoint)
{
    // ipv4: 127.0.0.1:12345 => EndPoint
    // ipv6: [0:1]:12345 => EndPoint

    std::string ip;
    uint16_t port;
    bool valid = false;

    std::vector<std::string> s;
    boost::split(s, _peer, boost::is_any_of("]"), boost::token_compress_on);
    if (s.size() == 2)
    {  // ipv6
        ip = s[0].data() + 1;
        port = boost::lexical_cast<int>(s[1].data() + 1);
        valid = true;
    }
    else if (s.size() == 1)
    {  // ipv4
        std::vector<std::string> v;
        boost::split(v, _peer, boost::is_any_of(":"), boost::token_compress_on);
        ip = v[0];
        port = boost::lexical_cast<uint16_t>(v[1]);
        valid = true;
    }

    valid = validIP(ip) && validPort(port);

    if (!valid)
    {
        WEBSOCKET_TOOL(WARNING) << LOG_DESC("peer is not valid ip:port format")
                                << LOG_KV("peer", _peer);
    }

    if (valid)
    {
        _endpoint.host = ip;
        _endpoint.port = port;
    }

    return valid;
}