#pragma once
#include "tdx.h"
#include "td/actor/actor.h"
#include "td/utils/as.h"
#include "td/utils/buffer.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/tl_helpers.h"
#include "td/utils/optional.h"
#include "td/actor/coro_task.h"
#include "td/net/FramedPipe.h"
#include "td/net/Pipe.h"
#include "td/net/utils.h"
#include <string>

namespace td {
class SslStream;
}  // namespace td

namespace cocoon {

// Binary slice helpers - convert slice to typed value
template <class T, class TT = T>
td::Result<TT> to(td::Slice s) {
  if (s.size() != sizeof(T)) {
    return td::Status::Error(PSLICE() << "Size mismatch in to(): got " << s.size() << " bytes, expected " << sizeof(T));
  }
  T result = td::as<T>(s.ubegin());
  return result;
}

// Binary slice helpers - read and consume typed value from slice
template <class T, class TT = T>
td::Result<TT> cut(td::Slice& s) {
  if (s.size() < sizeof(T)) {
    return td::Status::Error(PSLICE() << "Insufficient data in cut(): got " << s.size() << " bytes, need at least "
                                      << sizeof(T));
  }
  T result = td::as<T>(s.ubegin());
  s.remove_prefix(sizeof(T));
  return result;
}
struct AttestedPeerInfo;
// Create a server-side SSL stream using provided cert/key and policy verification
td::Result<td::SslStream> create_server_ssl_stream(tdx::CertAndKey cert_and_key, tdx::PolicyRef policy);

// Create a client-side SSL stream for the given host using provided cert/key and policy verification
td::Result<td::SslStream> create_client_ssl_stream(td::CSlice host, tdx::CertAndKey cert_and_key, tdx::PolicyRef policy,
                                                   bool enable_sni = true);

// Re-export framed I/O functions from td namespace for backward compatibility
using td::framed_read;
using td::framed_write;

/**
 * @brief Write a TL-serialized object with framing
 * @tparam T Type with store() method for TL serialization
 * @param writer Buffer to write to
 * @param object Object to serialize and write
 * @return Status indicating success or error
 */
template <class T>
td::Status framed_tl_write(td::ChainBufferWriter &writer, const T &object) {
  auto serialized = td::serialize(object);
  return td::framed_write(writer, serialized);
}

/**
 * @brief Read a TL-serialized object with framing
 * @tparam T Type with parse() method for TL deserialization
 * @param reader Buffer to read from
 * @return Optional containing the deserialized object if successful, or error status
 *         Returns empty optional if more data is needed (non-error case)
 */
template <class T>
td::Result<td::optional<T>> framed_tl_read(td::ChainBufferReader &reader) {
  td::BufferSlice message;
  TRY_RESULT(needed, td::framed_read(reader, message));

  // If needed > 0, we need more data (not an error)
  if (needed > 0) {
    return td::optional<T>{};
  }

  // Deserialize the message
  T object;
  TRY_STATUS(td::unserialize(object, message.as_slice()));
  return td::optional<T>(std::move(object));
}

// Move all available data from reader to writer
template <class L, class R>
void proxy_sockets(L &reader, R &writer) {
  // NB: do not call output_buffer() if there is nothing to write
  if (reader.input_buffer().empty()) {
    return;
  }
  writer.output_buffer().append(reader.input_buffer());
}

td::actor::StartedTask<td::BufferedFd<td::SocketFd>> socks5(td::SocketFd socket_fd, td::IPAddress dest,
                                                            td::string username, td::string password);
td::actor::StartedTask<td::Unit> proxy(td::Slice name, td::Pipe left, td::Pipe right);

td::actor::Task<std::pair<td::Pipe, AttestedPeerInfo>> wrap_tls_client(td::Slice name, td::Pipe pipe,
                                                                       tdx::CertAndKey cert_and_key,
                                                                       tdx::PolicyRef policy,
                                                                       const td::IPAddress &source,
                                                                       const td::IPAddress &destination);
td::actor::Task<std::pair<td::Pipe, AttestedPeerInfo>> wrap_tls_server(td::Slice name, td::Pipe pipe,
                                                                       tdx::CertAndKey cert_and_key,
                                                                       tdx::PolicyRef policy,
                                                                       const td::IPAddress &source,
                                                                       const td::IPAddress &destination);

/**
 * @brief Attested peer information for serialization
 * 
 * Contains comprehensive information about the attested peer including
 * source/destination addresses, attestation data, and user claims
 */
struct AttestedPeerInfo {
  tdx::AttestationData attestation_data;
  tdx::UserClaims user_claims;
  std::string source_ip;       // Source IP address as string
  int source_port;             // Source port
  std::string destination_ip;  // Destination IP address as string
  int destination_port;        // Destination port

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(attestation_data, storer);
    store(user_claims, storer);
    store(source_ip, storer);
    store(source_port, storer);
    store(destination_ip, storer);
    store(destination_port, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    parse(attestation_data, parser);
    parse(user_claims, parser);
    parse(source_ip, parser);
    parse(source_port, parser);
    parse(destination_ip, parser);
    parse(destination_port, parser);
  }
};

td::StringBuilder &operator<<(td::StringBuilder &sb, const AttestedPeerInfo &info);

/**
 * @brief Create attested peer info from basic attestation data, user claims, and addresses
 */
AttestedPeerInfo make_attested_peer_info(const tdx::AttestationData &attestation, const tdx::UserClaims &user_claims,
                                         const td::IPAddress &source, const td::IPAddress &destination);

struct ProxyState {
  std::string state_ = "Connecting";
  td::optional<td::IPAddress> source_;
  td::optional<td::IPAddress> destination_;
  std::string attestation_;       // short image hash or empty
  std::string attestation_type_;  // "TDX", "SGX", "None", or "fake TDX"
  bool finished_ = false;
  td::Status status;

  std::string short_desc() const {
    std::string desc;
    if (source_) {
      desc += PSTRING() << source_.value().get_ip_str() << ":" << source_.value().get_port();
    } else {
      desc += "?";
    }
    desc += " -> ";
    if (destination_) {
      desc += PSTRING() << destination_.value().get_ip_str() << ":" << destination_.value().get_port();
    } else {
      desc += "?";
    }
    if (!attestation_.empty()) {
      desc += " [" + attestation_ + " " + attestation_type_ + "]";
    }
    return desc;
  }

  void set_attestation(const tdx::AttestationData &info) {
    if (info.is_empty()) {
      attestation_ = "";
      attestation_type_ = "None";
    } else {
      auto hash = info.image_hash();
      attestation_ = td::hex_encode(hash.as_slice()).substr(0, 8) + "..";
      attestation_type_ = info.short_description();
    }
  }

  td::Status init_source(const td::SocketFd &socket) {
    td::IPAddress source_addr;
    TRY_STATUS(source_addr.init_peer_address(socket));
    source_ = source_addr;
    return td::Status::OK();
  }

  void update_state(td::Slice new_state) {
    state_ = new_state.str();
    LOG(INFO) << *this;
  }

  void finish(td::Status st) {
    finished_ = true;
    status = std::move(st);
    if (status.is_error()) {
      LOG(ERROR) << *this;
    } else {
      LOG(INFO) << *this;
    }
  }
};

td::StringBuilder &operator<<(td::StringBuilder &sb, const ProxyState &state);

}  // namespace cocoon