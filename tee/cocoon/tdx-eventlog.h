/*
 * tdx-eventlog.h
 * 
 * TDX Event Log (CCEL ACPI Table) parsing and RTMR replay.
 * Based on TCG PC Client Platform Firmware Profile Specification.
 */

#pragma once

#include "td/utils/Status.h"
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace cocoon {
namespace tdx_eventlog {

// RTMR constants
constexpr size_t RTMR_COUNT = 4;
constexpr size_t RTMR_SIZE = 48;  // SHA-384 digest size

// TCG Event Log Types (from TCG EFI Protocol Specification)
namespace EventType {
constexpr uint32_t EV_PREBOOT_CERT = 0x0;
constexpr uint32_t EV_POST_CODE = 0x1;
constexpr uint32_t EV_UNUSED = 0x2;
constexpr uint32_t EV_NO_ACTION = 0x3;
constexpr uint32_t EV_SEPARATOR = 0x4;
constexpr uint32_t EV_ACTION = 0x5;
constexpr uint32_t EV_EVENT_TAG = 0x6;
constexpr uint32_t EV_S_CRTM_CONTENTS = 0x7;
constexpr uint32_t EV_S_CRTM_VERSION = 0x8;
constexpr uint32_t EV_CPU_MICROCODE = 0x9;
constexpr uint32_t EV_PLATFORM_CONFIG_FLAGS = 0xa;
constexpr uint32_t EV_TABLE_OF_DEVICES = 0xb;
constexpr uint32_t EV_COMPACT_HASH = 0xc;
constexpr uint32_t EV_IPL = 0xd;
constexpr uint32_t EV_IPL_PARTITION_DATA = 0xe;
constexpr uint32_t EV_NONHOST_CODE = 0xf;
constexpr uint32_t EV_NONHOST_CONFIG = 0x10;
constexpr uint32_t EV_NONHOST_INFO = 0x11;
constexpr uint32_t EV_OMIT_BOOT_DEVICE_EVENTS = 0x12;

// EFI Event Types
constexpr uint32_t EV_EFI_EVENT_BASE = 0x80000000;
constexpr uint32_t EV_EFI_VARIABLE_DRIVER_CONFIG = EV_EFI_EVENT_BASE + 0x1;
constexpr uint32_t EV_EFI_VARIABLE_BOOT = EV_EFI_EVENT_BASE + 0x2;
constexpr uint32_t EV_EFI_BOOT_SERVICES_APPLICATION = EV_EFI_EVENT_BASE + 0x3;
constexpr uint32_t EV_EFI_BOOT_SERVICES_DRIVER = EV_EFI_EVENT_BASE + 0x4;
constexpr uint32_t EV_EFI_RUNTIME_SERVICES_DRIVER = EV_EFI_EVENT_BASE + 0x5;
constexpr uint32_t EV_EFI_GPT_EVENT = EV_EFI_EVENT_BASE + 0x6;
constexpr uint32_t EV_EFI_ACTION = EV_EFI_EVENT_BASE + 0x7;
constexpr uint32_t EV_EFI_PLATFORM_FIRMWARE_BLOB = EV_EFI_EVENT_BASE + 0x8;
constexpr uint32_t EV_EFI_HANDOFF_TABLES = EV_EFI_EVENT_BASE + 0x9;
constexpr uint32_t EV_EFI_PLATFORM_FIRMWARE_BLOB2 = EV_EFI_EVENT_BASE + 0xa;
constexpr uint32_t EV_EFI_HANDOFF_TABLES2 = EV_EFI_EVENT_BASE + 0xb;
constexpr uint32_t EV_EFI_VARIABLE_BOOT2 = EV_EFI_EVENT_BASE + 0xc;
constexpr uint32_t EV_EFI_HCRTM_EVENT = EV_EFI_EVENT_BASE + 0x10;
constexpr uint32_t EV_EFI_VARIABLE_AUTHORITY = EV_EFI_EVENT_BASE + 0xe0;
constexpr uint32_t EV_EFI_SPDM_FIRMWARE_BLOB = EV_EFI_EVENT_BASE + 0xe1;
constexpr uint32_t EV_EFI_SPDM_FIRMWARE_CONFIG = EV_EFI_EVENT_BASE + 0xe2;

const char* to_string(uint32_t type);
}  // namespace EventType

// TCG Algorithm Registry
namespace AlgorithmId {
constexpr uint16_t TPM_ALG_SHA256 = 0x000B;
constexpr uint16_t TPM_ALG_SHA384 = 0x000C;
constexpr uint16_t TPM_ALG_SHA512 = 0x000D;

const char* to_string(uint16_t alg);
size_t digest_size(uint16_t alg);
}  // namespace AlgorithmId

// Event log entry (parsed)
struct EventLogEntry {
  uint64_t address;        // Address in memory (log_area_start + offset)
  size_t length;           // Total length of this entry in bytes
  uint32_t rtmr_index;     // 0-3 for TDX RTMRs (td_register_index - 1)
  uint32_t event_type;
  std::string digest_raw;  // Raw digest bytes (not hex-encoded)
  std::string digest_hex;  // Hex-encoded digest for display
  uint16_t algorithm_id;
  std::string event_data;  // Raw event data (may contain binary)
  std::string raw_data;    // Complete raw entry for hex dump
};

// RTMR value (48 bytes for SHA-384)
using RtmrValue = std::array<uint8_t, RTMR_SIZE>;

// Parsed event log with replay capability
struct EventLog {
  uint64_t log_area_start;
  uint64_t log_area_length;
  std::map<uint16_t, uint16_t> digest_sizes;  // algorithm_id -> size
  std::vector<EventLogEntry> entries;
  
  // Replayed RTMR values (computed from event log)
  std::array<RtmrValue, RTMR_COUNT> replayed_rtmrs;
  bool rtmrs_computed = false;
  
  // Compute RTMRs by replaying all events
  void replay_rtmrs();
  
  // Get events for a specific RTMR
  std::vector<const EventLogEntry*> get_events_for_rtmr(uint32_t rtmr_index) const;
};

// Parse the event log from CCEL ACPI table
td::Result<EventLog> parse_event_log();

// Read actual RTMR values from sysfs
td::Result<RtmrValue> read_rtmr_raw(int index);

// Format RTMR value as hex string
std::string rtmr_to_hex(const RtmrValue& rtmr);

// Format hex dump of raw data
std::string format_hex_dump(uint64_t base_addr, const std::string& data);

// Render complete event log output
std::string render_event_log();

}  // namespace tdx_eventlog
}  // namespace cocoon

