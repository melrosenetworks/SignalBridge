/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/config/config_loader.h"
#include <yaml-cpp/yaml.h>
#include <fstream>

namespace signalbridge {

bool ConfigLoader::load(const std::string& path, ConduitConfig& config) {
    try {
        YAML::Node node = YAML::LoadFile(path);
        if (!node) return false;

        if (auto a = node["anonymisation"]) {
            config.anonymisation.enabled = a["enabled"].as<bool>(true);
            if (a["mcc"]) config.anonymisation.mcc = a["mcc"].as<std::string>("999");
            if (a["mnc"]) config.anonymisation.mnc = a["mnc"].as<std::string>("99");
            if (a["imsi_map_path"]) config.anonymisation.imsi_map_path = a["imsi_map_path"].as<std::string>("");
            if (a["replacement_byte"])
                config.anonymisation.replacement_byte = static_cast<uint8_t>(a["replacement_byte"].as<int>(0));
        }

        if (auto f = node["filter"]) {
            if (f["protocol_include"])
                for (auto v : f["protocol_include"]) config.filter.protocol_include.push_back(v.as<std::string>());
            if (f["protocol_exclude"])
                for (auto v : f["protocol_exclude"]) config.filter.protocol_exclude.push_back(v.as<std::string>());
            if (f["procedure_include"])
                for (auto v : f["procedure_include"]) config.filter.procedure_include.push_back(v.as<int>());
            if (f["procedure_exclude"])
                for (auto v : f["procedure_exclude"]) config.filter.procedure_exclude.push_back(v.as<int>());
            if (f["ip_allow"])
                for (auto v : f["ip_allow"]) config.filter.ip_allow.push_back(v.as<std::string>());
            if (f["ip_deny"])
                for (auto v : f["ip_deny"]) config.filter.ip_deny.push_back(v.as<std::string>());
            config.filter.drop_encrypted_nas = f["drop_encrypted_nas"].as<bool>(true);
        }

        if (auto in = node["inputs"])
            for (auto n : in) {
                InputConfig ic;
                ic.type = n["type"].as<std::string>("file");
                ic.path = n["path"].as<std::string>("");
                ic.address = n["address"].as<std::string>("");
                config.inputs.push_back(ic);
            }

        if (auto out = node["outputs"])
            for (auto n : out) {
                OutputConfig oc;
                oc.type = n["type"].as<std::string>("file");
                oc.path = n["path"].as<std::string>("");
                oc.address = n["address"].as<std::string>("");
                config.outputs.push_back(oc);
            }

        if (node["encryption_key"])
            config.encryption_key = node["encryption_key"].as<std::string>("");

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace signalbridge
