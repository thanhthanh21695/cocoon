#pragma once

#include "auto/tl/cocoon_api.h"
#include "errorcode.h"
#include "runners/BaseRunner.hpp"
#include "td/actor/ActorId.h"
#include "ProxyStats.h"
#include "td/actor/common.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"
#include <memory>
#include "ProxyClientInfo.h"
#include "ProxyWorkerConnectionInfo.h"
#include "runners/helpers/CountTokens.hpp"

namespace cocoon {

class ProxyRunner;

struct ProxyRunningRequest : public td::actor::Actor {
  ProxyRunningRequest(td::Bits256 id, td::Bits256 client_request_id, TcpClient::ConnectionId client_connection_id,
                      std::shared_ptr<ProxyClientInfo> client, std::shared_ptr<ProxyWorkerConnectionInfo> worker,
                      td::BufferSlice data, double timeout, td::int64 reserved_tokens,
                      td::actor::ActorId<ProxyRunner> runner, std::shared_ptr<ProxyStats> stats)
      : id_(id)
      , client_request_id_(client_request_id)
      , client_connection_id_(client_connection_id)
      , client_(std::move(client))
      , worker_(std::move(worker))
      , data_(std::move(data))
      , timeout_(timeout)
      , reserved_tokens_(reserved_tokens)
      , runner_(runner)
      , stats_(std::move(stats)) {
    coefficient_ = worker_->coefficient;
  }

  void start_up() override;

  void alarm() override {
    fail(td::Status::Error(ton::ErrorCode::timeout, "timeout in proxy"));
  }

  void receive_answer(ton::tl_object_ptr<cocoon_api::proxy_queryAnswer> ans);
  void receive_answer_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerError> ans);
  void receive_answer_part(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPart> ans);
  void receive_answer_part_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPartError> ans);
  void fail(td::Status error);
  void finish(bool is_success);

  auto stats() const {
    return stats_.get();
  }

  ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used() const {
    return ton::create_tl_object<cocoon_api::tokensUsed>(
        tokens_used_->prompt_tokens_used_, tokens_used_->cached_tokens_used_, tokens_used_->completion_tokens_used_,
        tokens_used_->reasoning_tokens_used_, tokens_used_->total_tokens_used_);
  }

 private:
  td::Bits256 id_;
  td::Bits256 client_request_id_;
  TcpClient::ConnectionId client_connection_id_;
  std::shared_ptr<ProxyClientInfo> client_;
  std::shared_ptr<ProxyWorkerConnectionInfo> worker_;
  td::BufferSlice data_;
  double timeout_;
  td::int64 reserved_tokens_;

  td::actor::ActorId<ProxyRunner> runner_;
  std::shared_ptr<ProxyStats> stats_;

  bool sent_answer_{false};

  auto run_time() const {
    return td::Clocks::monotonic() - start_time_monotonic_;
  }

  double start_time_monotonic_ = td::Clocks::monotonic();
  double start_time_unix_ = td::Clocks::system();
  td::int64 payload_parts_{0};
  td::int64 payload_bytes_{0};

  ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used_ =
      ton::create_tl_object<cocoon_api::tokensUsed>(0, 0, 0, 0, 0);

  td::int64 coefficient_;
};

}  // namespace cocoon
