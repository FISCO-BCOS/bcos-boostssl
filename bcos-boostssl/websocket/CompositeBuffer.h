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
 * @file CompositeBuffer.h
 * @author: octopus
 * @date 2021-08-23
 */
#pragma once

#include <bcos-utilities/Common.h>
#include <vector>

namespace bcos
{
namespace boostssl
{
namespace ws
{

class CompositeBuffer
{
private:
    std::vector<std::shared_ptr<bcos::bytes>> m_buffers{4};

public:
    void appendBuffer(const std::shared_ptr<bcos::bytes>& _buffer)
    {
        m_buffers.push_back(std::move(_buffer));
    }

    void appendBufferToHead(const std::shared_ptr<bcos::bytes>& _buffer)
    {
        m_buffers.insert(m_buffers.begin(), std::move(_buffer));
    }

    std::size_t size() const { return m_buffers.size(); }
    std::vector<std::shared_ptr<bcos::bytes>> buffers() const { return m_buffers; }
};

}  // namespace ws
}  // namespace boostssl
}  // namespace bcos