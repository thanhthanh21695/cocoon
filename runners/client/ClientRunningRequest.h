#pragma once

#include "auto/tl/cocoon_api.h"
#include "errorcode.h"
#include "http/http.h"
#include "runners/BaseRunner.hpp"
#include "td/actor/ActorId.h"
#include "td/actor/common.h"
#include "ClientProxyInfo.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "td/utils/port/Clocks.h"
#include "tl/TlObject.h"
#include "ClientStats.h"
#include <memory>

namespace cocoon {

class ClientRunningRequest : public td::actor::Actor {
 public:
  ClientRunningRequest(
      td::Bits256 request_id, std::unique_ptr<ton::http::HttpRequest> request,
      std::shared_ptr<ton::http::HttpPayload> payload,
      td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise,
      std::shared_ptr<ClientProxyInfo> proxy, TcpClient::ConnectionId proxy_connection_id, td::int32 min_config_version,
      td::actor::ActorId<ClientRunner> client_runner)
      : request_id_(request_id)
      , in_request_(std::move(request))
      , in_payload_(std::move(payload))
      , promise_(std::move(promise))
      , proxy_(std::move(proxy))
      , proxy_connection_id_(proxy_connection_id)
      , min_config_version_(min_config_version)
      , client_runner_(client_runner) {
  }

  void start_up() override;
  void alarm() override {
    if (promise_) {
      return_error(td::Status::Error(ton::ErrorCode::timeout, "timeout"));
    } else {
      finish_request(false);
    }
  }

  void on_payload_downloaded(td::BufferSlice downloaded_payload);

  void process_answer(ton::tl_object_ptr<cocoon_api::client_queryAnswer> ans);
  void process_answer_error(ton::tl_object_ptr<cocoon_api::client_queryAnswerError> ans);
  void process_answer_part(ton::tl_object_ptr<cocoon_api::client_queryAnswerPart> ans);
  void process_answer_part_error(ton::tl_object_ptr<cocoon_api::client_queryAnswerPartError> ans);

  void return_error_str(td::int32 ton_error_code, std::string error);
  void return_error(td::Status error) {
    return_error_str(error.code(), PSTRING() << "Internal data: " << error);
  }

  void finish_request(bool success);

  const std::shared_ptr<ClientStats> stats() const;

  auto run_time() const {
    return td::Clocks::monotonic() - started_at_;
  }

 private:
  td::Bits256 request_id_;
  std::unique_ptr<ton::http::HttpRequest> in_request_;
  std::shared_ptr<ton::http::HttpPayload> in_payload_;
  td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise_;
  std::shared_ptr<ClientProxyInfo> proxy_;
  TcpClient::ConnectionId proxy_connection_id_;
  td::uint32 min_config_version_;
  td::actor::ActorId<ClientRunner> client_runner_;
  std::shared_ptr<ton::http::HttpPayload> out_payload_;
  double started_at_ = td::Clocks::monotonic();
  double started_at_unix_ = td::Clocks::system();
  td::int64 payload_parts_{0};
  td::int64 payload_bytes_{0};
};

}  // namespace cocoon
