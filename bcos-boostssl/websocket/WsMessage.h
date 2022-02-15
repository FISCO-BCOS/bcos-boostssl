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
 * @file WsMessage.h
 * @author: octopus
 * @date 2021-07-28
 */
#pragma once

#include <bcos-utilities/Common.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <iterator>
#include <memory>
#include <utility>

namespace bcos
{
namespace boostssl
{
namespace ws
{
// the message format for ws protocol
class MessageFace
{
public:
    using Ptr = std::shared_ptr<MessageFace>;

public:
    virtual ~MessageFace() {}

    virtual uint16_t packetType() const = 0;
    virtual std::string seq() const = 0;
    virtual std::shared_ptr<bytes> payload() const = 0;

    virtual bool encode(bcos::bytes& _buffer) = 0;
    virtual int64_t decode(bytesConstRef _buffer) = 0;
};

class WsMessage : public MessageFace
{
public:
    using Ptr = std::shared_ptr<WsMessage>;
    // seq field length
    const static size_t SEQ_LENGTH = 32;
    /// type(2) + status(2) + seq(32) + data(N)
    const static size_t MESSAGE_MIN_LENGTH = 36;

public:
    WsMessage()
    {
        m_data = std::make_shared<bcos::bytes>();
    }

    virtual ~WsMessage() {}

public:
    virtual uint16_t packetType() const override { return m_type; }
    virtual void setPacketType(uint16_t _type){ m_type = _type; }
    virtual uint16_t status() { return m_status; }
    virtual void setStatus(uint16_t _status) { m_status = _status; }
    virtual std::string seq() const override { return m_seq; }
    virtual void setSeq(std::string _seq) { m_seq = _seq; }
    virtual std::shared_ptr<bcos::bytes> payload() const override { return m_data; }
    virtual void setPayload(std::shared_ptr<bcos::bytes> _data) { m_data = _data; }

public:
    virtual bool encode(bcos::bytes& _buffer) override;
    virtual int64_t decode(bytesConstRef _buffer) override;

private:
    uint16_t m_type{0};
    uint16_t m_status{0};
    std::string m_seq {SEQ_LENGTH, '0'};
    std::shared_ptr<bcos::bytes> m_data;
};


class WsMessageFactory
{
public:
    using Ptr = std::shared_ptr<WsMessageFactory>;
    WsMessageFactory() = default;
    virtual ~WsMessageFactory() {}

public:
    virtual std::string newSeq()
    {
        std::string seq = boost::uuids::to_string(boost::uuids::random_generator()());
        seq.erase(std::remove(seq.begin(), seq.end(), '-'), seq.end());
        return seq;
    }

    virtual std::shared_ptr<WsMessage> buildMessage()
    {
        auto msg = std::make_shared<WsMessage>();
        auto seq = newSeq();
        msg->setSeq(seq);
        return msg;
    }

    virtual std::shared_ptr<WsMessage> buildMessage(
        uint16_t _type, std::shared_ptr<bcos::bytes> _data)
    {
        auto msg = std::make_shared<WsMessage>();
        auto seq = newSeq();
        msg->setPacketType(_type);
        msg->setPayload(_data);
        msg->setSeq(seq);
        return msg;
    }
};

}  // namespace ws
}  // namespace boostssl
}  // namespace bcos