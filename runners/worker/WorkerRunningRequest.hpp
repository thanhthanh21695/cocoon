#pragma once

#include "common/bitstring.h"
#include "errorcode.h"
#include "runners/BaseRunner.hpp"
#include "http/http.h"
#include "td/actor/ActorId.h"
#include "td/actor/common.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "WorkerStats.h"
#include "td/utils/port/Clocks.h"
#include "runners/helpers/CountTokens.hpp"
#include <memory>

namespace cocoon {

class WorkerRunner;

class WorkerRunningRequest : public td::actor::Actor {
 public:
  WorkerRunningRequest(td::Bits256 proxy_request_id, TcpClient::ConnectionId proxy_connection_id, td::BufferSlice data,
                       double timeout, std::string model_base_name, td::int32 coefficient,
                       std::shared_ptr<RunnerConfig> runner_config, td::actor::ActorId<WorkerRunner> runner,
                       std::shared_ptr<WorkerStats> stats);

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(timeout_);
    start_request();
  }

  void alarm() override {
    send_error(td::Status::Error(ton::ErrorCode::timeout, "worker: timeout"));
  }

  auto run_time() const {
    return td::Clocks::monotonic() - started_at_;
  }

  void start_request();
  void process_request_response(
      std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>> ans);
  void send_error(td::Status error);
  void send_answer(std::unique_ptr<ton::http::HttpResponse> response, td::BufferSlice payload,
                   bool payload_is_completed);
  void send_payload_part(td::BufferSlice payload_part, bool payload_is_completed);
  void finish_request(bool is_success);

  WorkerStats *stats() {
    return stats_.get();
  }

 private:
  td::Bits256 proxy_request_id_;
  TcpClient::ConnectionId proxy_connection_id_;
  td::BufferSlice data_;
  double timeout_;
  std::string model_base_name_;
  td::actor::ActorId<WorkerRunner> runner_;
  std::shared_ptr<WorkerStats> stats_;

  td::int32 payload_parts_{0};
  td::int64 payload_bytes_{0};
  double started_at_ = td::Clocks::monotonic();
  double started_at_unix_ = td::Clocks::system();
  bool completed_{false};
  bool sent_answer_{false};

  std::unique_ptr<TokenCounter> tokens_counter_;
};

}  // namespace cocoon
