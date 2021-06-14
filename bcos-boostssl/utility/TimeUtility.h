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
 * @file TimeUtility.h
 * @author: octopus
 * @date 2021-05-06
 */

#pragma once
#include <cstdint>

namespace boostssl {
namespace utility {

class TimeUtility {
public:
  TimeUtility() = delete;
  ~TimeUtility() = delete;

public:
  /// Get the current time in seconds since the epoch in UTC(ms)
  static uint64_t utcTime();
  static uint64_t utcSteadyTime();

  /// Get the current time in seconds since the epoch in UTC(us)
  static uint64_t utcTimeUs();
  static uint64_t utcSteadyTimeUs();
};

} // namespace utility
} // namespace boostssl