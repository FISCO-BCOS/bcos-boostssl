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
 * @brief: Socket inteface
 * @file SocketFace.h
 * @author octopus
 * @date 2021-06-07
 */

#pragma once
#include <bcos-boostssl/network/Common.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>

namespace boostssl {
namespace net {
class SocketFace {
public:
  SocketFace() = default;

  virtual ~SocketFace(){};
  virtual bool isConnected() const = 0;
  virtual void close() = 0;
  virtual bi::tcp::endpoint remoteEndpoint(
      boost::system::error_code ec = boost::system::error_code()) = 0;
  virtual bi::tcp::endpoint
  localEndpoint(boost::system::error_code ec = boost::system::error_code()) = 0;

  virtual bi::tcp::socket &ref() = 0;
  virtual ba::ssl::stream<bi::tcp::socket> &sslref() = 0;

  virtual const NodeIPEndpoint &nodeIPEndpoint() const = 0;
  virtual void setNodeIPEndpoint(NodeIPEndpoint _nodeIPEndpoint) = 0;
};
} // namespace net
} // namespace boostssl
