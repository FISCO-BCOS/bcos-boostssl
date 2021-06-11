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
 * (c) 2016-2018 fisco-dev contributors.
 */
/** @file ContextConfig.h
 *  @author octopus
 *  @date 2021-06-14
 */

#pragma once
#include <bcos-boostssl/context/Common.h>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <memory>

namespace boostssl {
namespace context {

class ContextConfig {
public:
  using Ptr = std::shared_ptr<ContextConfig>;

  ContextConfig() = default;
  ~ContextConfig() = default;

public:
  // cert for ssl connection
  struct CertConfig {
    std::string caCert;
    std::string nodeKey;
    std::string nodeCert;
  };

  // cert for sm ssl connection
  struct SMCertConfig {
    std::string caCert;
    std::string nodeCert;
    std::string nodeKey;
    std::string enNodeCert;
    std::string enNodeKey;
  };

public:
  /**
   * @brief: loads configuration items from the boostssl.ini
   * @param _configPath:
   * @return void
   */
  void initConfig(std::string const &_configPath);
  // loads ca configuration items from the configuration file
  void initCertConfig(const boost::property_tree::ptree &_pt);
  // loads sm ca configuration items from the configuration file
  void initSMCertConfig(const boost::property_tree::ptree &_pt);
  // check if file exist, exception will be throw if the file not exist
  void checkFileExist(const std::string &_path);

public:
  std::string sslType() const { return m_sslType; }
  CertConfig certConfig() const { return m_certConfig; }
  SMCertConfig smCertConfig() const { return m_smCertConfig; }

private:
  // ssl type, support ssl && tassl_sm
  std::string m_sslType;
  // cert config for ssl
  CertConfig m_certConfig;
  SMCertConfig m_smCertConfig;
};

} // namespace context
} // namespace boostssl