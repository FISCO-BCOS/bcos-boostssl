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
 * @file WsVersion.h
 * @author: octopus
 * @date 2021-07-30
 */
#pragma once

#include <cstdint>
namespace bcos
{
namespace boostssl
{
namespace ws
{
enum WsProtocolVersion : uint32_t
{
    None = 0,
    v1 = 1,
    // Focus: update current when websocket protocol upgrade
    current = v1
};
}
}  // namespace boostssl
}  // namespace bcos