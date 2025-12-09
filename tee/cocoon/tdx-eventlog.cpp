/*
 * tdx-eventlog.cpp
 * TDX Event Log (CCEL ACPI Table) parsing and RTMR replay.
 */

#include "tdx-eventlog.h"
#include "health-metrics.h"
#include "utils.h"

#include "td/utils/format.h"
#include "td/utils/Parser.h"
#include "td/utils/Slice.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/ScopeGuard.h"

#include <openssl/sha.h>

#include <cstring>


namespace cocoon::tdx_eventlog {

// ============================================================================
// Event Type and Algorithm ID String Conversion
// ============================================================================

const char* EventType::to_string(uint32_t type) {
  switch (type) {
    case EV_PREBOOT_CERT:
      return "EV_PREBOOT_CERT";
    case EV_POST_CODE:
      return "EV_POST_CODE";
    case EV_NO_ACTION:
      return "EV_NO_ACTION";
    case EV_SEPARATOR:
      return "EV_SEPARATOR";
    case EV_ACTION:
      return "EV_ACTION";
    case EV_EVENT_TAG:
      return "EV_EVENT_TAG";
    case EV_S_CRTM_CONTENTS:
      return "EV_S_CRTM_CONTENTS";
    case EV_S_CRTM_VERSION:
      return "EV_S_CRTM_VERSION";
    case EV_CPU_MICROCODE:
      return "EV_CPU_MICROCODE";
    case EV_PLATFORM_CONFIG_FLAGS:
      return "EV_PLATFORM_CONFIG_FLAGS";
    case EV_TABLE_OF_DEVICES:
      return "EV_TABLE_OF_DEVICES";
    case EV_COMPACT_HASH:
      return "EV_COMPACT_HASH";
    case EV_IPL:
      return "EV_IPL";
    case EV_IPL_PARTITION_DATA:
      return "EV_IPL_PARTITION_DATA";
    case EV_NONHOST_CODE:
      return "EV_NONHOST_CODE";
    case EV_NONHOST_CONFIG:
      return "EV_NONHOST_CONFIG";
    case EV_NONHOST_INFO:
      return "EV_NONHOST_INFO";
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
      return "EV_EFI_VARIABLE_DRIVER_CONFIG";
    case EV_EFI_VARIABLE_BOOT:
      return "EV_EFI_VARIABLE_BOOT";
    case EV_EFI_BOOT_SERVICES_APPLICATION:
      return "EV_EFI_BOOT_SERVICES_APPLICATION";
    case EV_EFI_BOOT_SERVICES_DRIVER:
      return "EV_EFI_BOOT_SERVICES_DRIVER";
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
      return "EV_EFI_RUNTIME_SERVICES_DRIVER";
    case EV_EFI_GPT_EVENT:
      return "EV_EFI_GPT_EVENT";
    case EV_EFI_ACTION:
      return "EV_EFI_ACTION";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
      return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
    case EV_EFI_HANDOFF_TABLES:
      return "EV_EFI_HANDOFF_TABLES";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB2:
      return "EV_EFI_PLATFORM_FIRMWARE_BLOB2";
    case EV_EFI_HANDOFF_TABLES2:
      return "EV_EFI_HANDOFF_TABLES2";
    case EV_EFI_VARIABLE_BOOT2:
      return "EV_EFI_VARIABLE_BOOT2";
    case EV_EFI_HCRTM_EVENT:
      return "EV_EFI_HCRTM_EVENT";
    case EV_EFI_VARIABLE_AUTHORITY:
      return "EV_EFI_VARIABLE_AUTHORITY";
    case EV_EFI_SPDM_FIRMWARE_BLOB:
      return "EV_EFI_SPDM_FIRMWARE_BLOB";
    case EV_EFI_SPDM_FIRMWARE_CONFIG:
      return "EV_EFI_SPDM_FIRMWARE_CONFIG";
    default:
      return "UNKNOWN";
  }
}

const char* AlgorithmId::to_string(uint16_t alg) {
  switch (alg) {
    case TPM_ALG_SHA256:
      return "SHA256";
    case TPM_ALG_SHA384:
      return "SHA384";
    case TPM_ALG_SHA512:
      return "SHA512";
    default:
      return "UNKNOWN";
  }
}

size_t AlgorithmId::digest_size(uint16_t alg) {
  switch (alg) {
    case TPM_ALG_SHA256:
      return 32;
    case TPM_ALG_SHA384:
      return 48;
    case TPM_ALG_SHA512:
      return 64;
    default:
      return 0;
  }
}

// ============================================================================
// CCEL ACPI Table (per ACPI 6.5 spec)
// ============================================================================

#pragma pack(push, 1)
struct CcelHeader {
  char signature[4];  // "CCEL"
  uint32_t length;
  uint8_t revision;
  uint8_t checksum;
  char oem_id[6];
  char oem_table_id[8];
  uint32_t oem_revision;
  uint32_t creator_id;
  uint32_t creator_revision;
  uint8_t cc_type;  // 2 = TDX
  uint8_t cc_subtype;
  uint16_t reserved;
  uint64_t log_area_minimum_length;
  uint64_t log_area_start_address;
};
#pragma pack(pop)

// ============================================================================
// Low-Level Utilities
// ============================================================================

static td::Result<std::string> read_file(td::CSlice path, size_t max_size = 1024 * 1024) {
  TRY_RESULT(fd, td::FileFd::open(path.str(), td::FileFd::Read));
  SCOPE_EXIT {
    fd.close();
  };

  std::string result;
  std::string buffer(4096, '\0');
  while (result.size() < max_size) {
    TRY_RESULT(r, fd.read(buffer));
    if (r == 0) {
      break;
    }
    result.append(buffer.data(), r);
  }
  return result;
}

static td::Result<td::Slice> cut_bytes(td::Slice& s, size_t n) {
  if (s.size() < n) {
    return td::Status::Error("Insufficient data");
  }
  auto result = s.substr(0, n);
  s.remove_prefix(n);
  return result;
}

// SHA384 wrapper returning RtmrValue
static RtmrValue compute_sha384(td::Slice data) {
  RtmrValue result{};
  SHA384(data.ubegin(), data.size(), result.data());
  return result;
}

// Extend RTMR: new = SHA384(old || digest)
static void extend_rtmr(RtmrValue& rtmr, td::Slice digest) {
  CHECK(digest.size() == RTMR_SIZE);
  std::array<uint8_t, RTMR_SIZE * 2> buf{};
  std::copy(rtmr.begin(), rtmr.end(), buf.begin());
  std::copy(digest.begin(), digest.end(), buf.begin() + RTMR_SIZE);
  rtmr = compute_sha384(td::Slice(reinterpret_cast<char*>(buf.data()), buf.size()));
}

std::string rtmr_to_hex(const RtmrValue& rtmr) {
  return td::buffer_to_hex(td::Slice(reinterpret_cast<const char*>(rtmr.data()), rtmr.size()));
}

// ============================================================================
// CCEL Parsing
// ============================================================================

static td::Result<CcelHeader> parse_ccel_header() {
  TRY_RESULT(data, read_file("/sys/firmware/acpi/tables/CCEL", 4096));
  TRY_RESULT(h, to<CcelHeader>(data));
  if (std::strncmp(h.signature, "CCEL", 4) != 0) {
    return td::Status::Error("Invalid CCEL signature");
  }
  return h;
}

static td::Result<size_t> parse_spec_id_header(td::Slice data, EventLog& log) {
  auto orig = data;

  TRY_RESULT(reg_index, cut<uint32_t>(data));
  (void)reg_index;
  TRY_RESULT(event_type, cut<uint32_t>(data));
  if (event_type != EventType::EV_NO_ACTION) {
    return td::Status::Error("Expected EV_NO_ACTION");
  }

  TRY_RESULT(digest_count, cut<uint32_t>(data));
  (void)digest_count;

  TRY_STATUS(cut_bytes(data, 20));  // Zero digest (SHA1 compat)
  TRY_STATUS(cut_bytes(data, 24));  // Signature + platform class + spec version + errata

  TRY_RESULT(num_algs, cut<uint32_t>(data));

  for (uint32_t i = 0; i < num_algs; i++) {
    TRY_RESULT(alg_id, cut<uint16_t>(data));
    TRY_RESULT(size, cut<uint16_t>(data));
    log.digest_sizes[alg_id] = size;
  }

  TRY_RESULT(vendor_size, cut<uint8_t>(data));
  TRY_STATUS(cut_bytes(data, vendor_size));

  return orig.size() - data.size();
}

static td::Result<size_t> parse_event_entry(td::Slice data, const EventLog& log, EventLogEntry& entry) {
  auto orig = data;

  TRY_RESULT(reg_index, cut<uint32_t>(data));
  entry.rtmr_index = reg_index > 0 ? reg_index - 1 : 0;

  TRY_RESULT(event_type, cut<uint32_t>(data));
  entry.event_type = event_type;

  TRY_RESULT(digest_count, cut<uint32_t>(data));

  for (uint32_t i = 0; i < digest_count; i++) {
    TRY_RESULT(alg_id, cut<uint16_t>(data));

    auto it = log.digest_sizes.find(alg_id);
    size_t digest_size = it != log.digest_sizes.end() ? it->second : AlgorithmId::digest_size(alg_id);
    if (digest_size == 0) {
      return td::Status::Error("Unknown algorithm");
    }

    TRY_RESULT(digest, cut_bytes(data, digest_size));

    if (entry.digest_raw.empty()) {
      entry.algorithm_id = alg_id;
      entry.digest_raw = digest.str();
      entry.digest_hex = td::buffer_to_hex(digest);
    }
  }

  TRY_RESULT(event_size, cut<uint32_t>(data));
  TRY_RESULT(event_data, cut_bytes(data, event_size));
  entry.event_data = event_data.str();

  entry.length = orig.size() - data.size();
  entry.raw_data = orig.substr(0, entry.length).str();

  return entry.length;
}

// ============================================================================
// EventLog Methods
// ============================================================================

std::vector<const EventLogEntry*> EventLog::get_events_for_rtmr(uint32_t idx) const {
  std::vector<const EventLogEntry*> result;
  for (const auto& e : entries) {
    if (e.rtmr_index == idx) {
      result.push_back(&e);
    }
  }
  return result;
}

void EventLog::replay_rtmrs() {
  if (rtmrs_computed) {
    return;
  }
  for (auto& r : replayed_rtmrs) {
    r.fill(0);
  }

  for (const auto& e : entries) {
    if (e.rtmr_index >= RTMR_COUNT || e.digest_raw.size() != RTMR_SIZE) {
      continue;
    }
    extend_rtmr(replayed_rtmrs[e.rtmr_index], e.digest_raw);
  }
  rtmrs_computed = true;
}

// ============================================================================
// Public API
// ============================================================================

td::Result<EventLog> parse_event_log() {
  EventLog log;

  TRY_RESULT(h, parse_ccel_header());
  log.log_area_start = h.log_area_start_address;
  log.log_area_length = h.log_area_minimum_length;

  TRY_RESULT(file_data, read_file("/sys/firmware/acpi/tables/data/CCEL", log.log_area_length));

  td::Slice data = file_data;
  TRY_RESULT(spec_size, parse_spec_id_header(data, log));
  data.remove_prefix(spec_size);

  while (!data.empty()) {
    if (data.size() >= 4 && td::as<uint32_t>(data.ubegin()) == 0xFFFFFFFF) {
      break;
    }

    EventLogEntry entry;
    entry.address = log.log_area_start + (file_data.size() - data.size());
    TRY_RESULT(consumed, parse_event_entry(data, log, entry));

    if (entry.event_type != EventType::EV_NO_ACTION) {
      log.entries.push_back(std::move(entry));
    }
    data.remove_prefix(consumed);
  }

  return log;
}

td::Result<RtmrValue> read_rtmr_raw(int index) {
  if (index < 0 || index >= static_cast<int>(RTMR_COUNT)) {
    return td::Status::Error("Invalid RTMR index");
  }
  auto path = PSTRING() << "/sys/class/misc/tdx_guest/measurements/rtmr" << index << ":sha384";
  TRY_RESULT(data, metrics::read_proc_file(path, 4096));

  while (!data.empty() && (data.back() == '\n' || data.back() == ' ')) {
    data.pop_back();
  }
  return to<RtmrValue>(data);
}

// ============================================================================
// Event Data Formatting (TCG spec parsers)
// ============================================================================

static bool is_printable(char c) {
  return c >= 32 && c < 127;
}

static td::Result<std::string> extract_ascii(td::Slice data) {
  std::string result;
  for (char c : data) {
    if (c == 0) {
      break;
    }
    if (is_printable(c)) {
      result += c;
    }
  }
  if (result.empty()) {
    return td::Status::Error("No ASCII content");
  }
  return result;
}

static std::string decode_utf16le(td::Slice data) {
  std::string result;
  for (size_t i = 0; i + 1 < data.size(); i += 2) {
    auto ch = static_cast<uint16_t>(static_cast<uint8_t>(data[i]) | (static_cast<uint16_t>(data[i + 1]) << 8));
    if (ch == 0) {
      break;
    }
    result += is_printable(static_cast<char>(ch)) ? static_cast<char>(ch) : '?';
  }
  return result;
}

// Check if name is Boot#### (4 hex digits)
static bool is_boot_option(td::Slice name) {
  if (name.size() != 8 || !td::begins_with(name, "Boot")) {
    return false;
  }
  for (int i = 4; i < 8; i++) {
    if (!td::is_hex_digit(name[i])) {
      return false;
    }
  }
  return true;
}

// Parse UEFI_VARIABLE_DATA: GUID(16) + NameLen(8) + DataLen(8) + Name[] + Data[]
static td::Result<std::string> parse_efi_variable(td::Slice data) {
  TRY_STATUS(cut_bytes(data, 16));  // GUID
  TRY_RESULT(name_len, cut<uint64_t>(data));
  TRY_RESULT(data_len, cut<uint64_t>(data));

  // Check reasonable limit first to avoid overflow in name_len * 2
  if (name_len > 1000 || name_len * 2 > data.size()) {
    return td::Status::Error("Invalid name length");
  }

  TRY_RESULT(name_bytes, cut_bytes(data, name_len * 2));
  auto name = decode_utf16le(name_bytes);
  if (name.empty()) {
    return td::Status::Error("Empty variable name");
  }

  std::string result = "Variable: \"" + name + "\"";

  // For Boot#### variables, parse EFI_LOAD_OPTION to get description
  if (is_boot_option(name) && data_len > 6 && cut_bytes(data, 6).is_ok()) {
    auto desc = decode_utf16le(data);
    if (!desc.empty()) {
      result += " = \"" + desc + "\"";
    }
  }
  return result;
}

static td::Result<std::string> parse_boot_app(td::Slice data) {
  for (size_t i = 0; i + 4 < data.size(); i++) {
    if (data[i] == '\\' && data[i + 1] == 0) {
      auto path = decode_utf16le(data.substr(i));
      if (path.size() >= 4 && (path.find(".efi") != std::string::npos || path.find("EFI") != std::string::npos)) {
        return "Boot: \"" + path + "\"";
      }
    }
  }
  return td::Status::Error("No boot path found");
}

static td::Result<std::string> parse_prefixed_desc(td::Slice data) {
  if (data.empty()) {
    return td::Status::Error("Empty data");
  }
  TRY_RESULT(len, cut<uint8_t>(data));
  if (len == 0 || len > data.size()) {
    return td::Status::Error("Invalid length");
  }
  return extract_ascii(data.substr(0, len));
}

static td::Result<std::string> parse_event_tag(td::Slice data) {
  TRY_RESULT(tag_id, cut<uint32_t>(data));
  (void)tag_id;
  TRY_RESULT(data_size, cut<uint32_t>(data));

  if (data_size == 0 || data_size > data.size()) {
    return td::Status::Error("Invalid event tag size");
  }
  return extract_ascii(data.substr(0, data_size));
}

static td::Result<std::string> try_format_event_data(td::Slice data, uint32_t type) {
  switch (type) {
    case EventType::EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EventType::EV_EFI_VARIABLE_BOOT:
    case EventType::EV_EFI_VARIABLE_BOOT2:
    case EventType::EV_EFI_VARIABLE_AUTHORITY:
      return parse_efi_variable(data);

    case EventType::EV_EFI_GPT_EVENT:
      if (data.str().find("EFI PART") != std::string::npos) {
        return std::string("GPT Partition Table");
      }
      return td::Status::Error("Unknown GPT format");

    case EventType::EV_EFI_BOOT_SERVICES_APPLICATION:
    case EventType::EV_EFI_BOOT_SERVICES_DRIVER:
      return parse_boot_app(data);

    case EventType::EV_EFI_ACTION:
    case EventType::EV_PLATFORM_CONFIG_FLAGS:
    case EventType::EV_NONHOST_CONFIG:
    case EventType::EV_NONHOST_INFO:
    case EventType::EV_IPL: {
      TRY_RESULT(s, extract_ascii(data));
      return "\"" + s + "\"";
    }

    case EventType::EV_SEPARATOR: {
      TRY_RESULT(val, to<uint32_t>(data));
      return std::string(val == 0 ? "Separator (success)" : "Separator (error)");
    }

    case EventType::EV_EFI_PLATFORM_FIRMWARE_BLOB2: {
      TRY_RESULT(s, parse_prefixed_desc(data));
      return "Firmware: \"" + s + "\"";
    }

    case EventType::EV_EFI_HANDOFF_TABLES2: {
      TRY_RESULT(s, parse_prefixed_desc(data));
      return "Table: \"" + s + "\"";
    }

    case EventType::EV_EVENT_TAG: {
      TRY_RESULT(s, parse_event_tag(data));
      return "\"" + s + "\"";
    }
    default:
      return td::Status::Error("Unknown format");
  }
}

static std::string format_event_data(td::Slice data, uint32_t type) {
  if (data.empty()) {
    return "(empty)";
  }
  auto r = try_format_event_data(data, type);
  if (r.is_ok()) {
    return r.move_as_ok();
  }
  return "(" + std::to_string(data.size()) + " bytes)";
}

// ============================================================================
// Rendering
// ============================================================================

static void hex_addr(td::StringBuilder& sb, uint64_t addr) {
  static constexpr char hex[] = "0123456789ABCDEF";
  for (int i = 28; i >= 0; i -= 4) {
    sb << hex[(addr >> i) & 0xF];
  }
}

static void hex_byte(td::StringBuilder& sb, uint8_t b) {
  static constexpr char hex[] = "0123456789ABCDEF";
  sb << hex[b >> 4] << hex[b & 0xF];
}

static std::string format_hex_dump(uint64_t addr, td::Slice data) {
  td::StringBuilder sb;
  sb << "RAW DATA: ----------------------------------------------\n";

  for (size_t i = 0; i < data.size(); i += 16) {
    hex_addr(sb, addr + i);
    sb << "  ";

    for (size_t j = 0; j < 16; j++) {
      if (i + j < data.size()) {
        hex_byte(sb, static_cast<uint8_t>(data[i + j]));
        sb << " ";
      } else {
        sb << "   ";
      }
      if (j == 7) {
        sb << " ";
      }
    }

    sb << " ";
    for (size_t j = 0; j < 16 && i + j < data.size(); j++) {
      char c = data[i + j];
      sb << (is_printable(c) ? c : '.');
    }
    sb << "\n";
  }

  sb << "RAW DATA: ----------------------------------------------";
  return sb.as_cslice().str();
}

static constexpr td::CSlice ATTESTATION_LOG = "/var/log/tdx-attestation.log";

static std::vector<std::string> read_attestation_log() {
  std::vector<std::string> entries;
  auto r = read_file(ATTESTATION_LOG);
  if (r.is_error()) {
    return entries;
  }

  td::ConstParser parser(r.ok());
  while (!parser.empty()) {
    auto line = parser.read_till_nofail('\n');
    parser.skip_nofail('\n');
    if (!line.empty()) {
      entries.push_back(line.str());
    }
  }
  return entries;
}

std::string render_event_log() {
  td::StringBuilder out;
  auto log_r = parse_event_log();

  if (log_r.is_error()) {
    out << "Error reading event log: " << log_r.error().message() << "\n";
    return out.as_cslice().str();
  }
  auto log = log_r.move_as_ok();

  // Spec ID header
  out << "==== TDX Event Log Entry - 0 [" << td::format::as_hex(log.log_area_start) << "] ====\n";
  out << "RTMR              : -1\n";
  out << "Type              : 0x3 (EV_NO_ACTION)\n";
  out << "Algorithms Number : " << log.digest_sizes.size() << "\n";
  for (const auto& [alg, sz] : log.digest_sizes) {
    out << "  Algorithms[" << td::format::as_hex(alg) << "] Size: " << (sz * 8) << "\n";
  }
  out << "\n";

  // Event entries
  int idx = 1;
  for (const auto& e : log.entries) {
    out << "==== TDX Event Log Entry - " << idx++ << " [" << td::format::as_hex(e.address) << "] ====\n";
    out << "RTMR              : " << e.rtmr_index << "\n";
    out << "Type              : " << td::format::as_hex(e.event_type) << " (" << EventType::to_string(e.event_type)
        << ")\n";
    out << "Length            : " << e.length << "\n";
    out << "Algorithms ID     : " << e.algorithm_id << " (TPM_ALG_" << AlgorithmId::to_string(e.algorithm_id) << ")\n";
    out << "Digest[0] : " << e.digest_hex << "\n";
    out << "Event Data        : " << format_event_data(e.event_data, e.event_type) << "\n";
    out << format_hex_dump(e.address, td::Slice(e.raw_data)) << "\n\n";
  }

  // Replay RTMRs
  log.replay_rtmrs();
  auto attestation = read_attestation_log();

  if (!attestation.empty()) {
    out << "\n==== Custom Attestation Log (" << ATTESTATION_LOG << ") ====\n";
    out << "Entries extended into RTMR3:\n";
    for (size_t i = 0; i < attestation.size(); i++) {
      auto hash = compute_sha384(attestation[i]);
      out << "  [" << i << "] \"" << attestation[i] << "\"\n";
      out << "      SHA384: " << rtmr_to_hex(hash) << "\n";
      extend_rtmr(log.replayed_rtmrs[3], td::Slice(reinterpret_cast<char*>(hash.data()), hash.size()));
    }
    out << "\n";
  }

  out << "\n==== Replayed RTMR values from event log";
  if (!attestation.empty())
    out << " + attestation log";
  out << " ====\n";
  for (size_t i = 0; i < RTMR_COUNT; i++) {
    out << "rtmr_" << i << " : " << rtmr_to_hex(log.replayed_rtmrs[i]) << "\n";
  }

  // Compare with actual values
  out << "\n==== Actual RTMR values from sysfs ====\n";
  bool all_match = true;
  for (size_t i = 0; i < RTMR_COUNT; i++) {
    auto r = read_rtmr_raw(static_cast<int>(i));
    if (r.is_ok()) {
      auto actual = rtmr_to_hex(r.ok());
      auto expected = rtmr_to_hex(log.replayed_rtmrs[i]);
      bool match = (actual == expected);
      out << "rtmr_" << i << " : " << actual;
      if (match) {
        out << "  [MATCH]\n";
      } else {
        out << "  [MISMATCH]\n         expected: " << expected << "\n";
        all_match = false;
      }
    } else {
      out << "rtmr_" << i << " : (not available)\n";
      all_match = false;
    }
  }

  // Summary
  out << "\n==== Summary ====\n";
  out << "Total CCEL events: " << (log.entries.size() + 1) << "\n";
  if (!attestation.empty()) {
    out << "Custom attestation entries: " << attestation.size() << "\n";
  }
  for (size_t i = 0; i < RTMR_COUNT; i++) {
    size_t count = log.get_events_for_rtmr(static_cast<uint32_t>(i)).size();
    if (i == 3)
      count += attestation.size();
    out << "RTMR" << i << " events: " << count << "\n";
  }
  out << "Verification: " << (all_match ? "ALL RTMR VALUES MATCH" : "RTMR MISMATCH DETECTED") << "\n";

  return out.as_cslice().str();
}

} // namespace cocoon::tdx_eventlog

