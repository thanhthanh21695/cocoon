#include "ProxyRunningRequest.hpp"
#include "ProxyRunner.hpp"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/ton_api.h"
#include "errorcode.h"
#include "keys/encryptor.h"

#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "td/actor/actor.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"

namespace cocoon {

void ProxyRunningRequest::start_up() {
  LOG(INFO) << "starting proxy request " << id_.to_hex() << ", worker connection id " << worker_->connection_id
            << " client_request_id=" << client_request_id_.to_hex();

  alarm_timestamp() = td::Timestamp::in(timeout_);

  stats()->requests_received++;

  auto R = cocoon::fetch_tl_object<cocoon_api::http_request>(data_.as_slice(), true);
  if (R.is_error()) {
    fail(R.move_as_error_prefix("proxy: received incorrect answer: "));
    return;
  }
  auto req = R.move_as_ok();
  stats()->request_bytes_received += (double)req->payload_.size();

  auto fwd_query = cocoon::create_serialize_tl_object<cocoon_api::proxy_runQuery>(
      std::move(data_), worker_->info->signed_payment(), coefficient_, timeout_ * 0.95, id_);

  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, worker_->connection_id,
                          std::move(fwd_query));
}

void ProxyRunningRequest::receive_answer(ton::tl_object_ptr<cocoon_api::proxy_queryAnswer> ans) {
  if (sent_answer_) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "out of order answer parts"));
    return;
  }

  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received answer";

  auto http_ans = cocoon::fetch_tl_object<cocoon_api::http_response>(ans->answer_.as_slice(), true).move_as_ok();
  if (http_ans->payload_.size() > 0) {
    stats()->answer_bytes_sent += (double)http_ans->payload_.size();
    payload_parts_++;
    payload_bytes_ += http_ans->payload_.size();
  }

  tokens_used_ = std::move(ans->tokens_used_);

  // Add proxy timing headers to the existing HTTP response using Unix timestamps
  http_ans->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(
      "X-Cocoon-Proxy-Start", PSTRING() << td::StringBuilder::FixedDouble(start_time_unix_, 6)));
  http_ans->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(
      "X-Cocoon-Proxy-End", PSTRING() << td::StringBuilder::FixedDouble(td::Clocks::system(), 6)));
  
  // Re-serialize the modified HTTP response
  auto modified_answer = cocoon::serialize_tl_object(http_ans, true);
  
  auto res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswer>(
      std::move(modified_answer), ans->is_completed_, client_request_id_, tokens_used());

  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));

  sent_answer_ = true;

  if (ans->is_completed_) {
    finish(true);
  } else {
    if (tokens_used_->total_tokens_used_ > reserved_tokens_) {
      return fail(td::Status::Error(ton::ErrorCode::error,
                                    PSTRING() << "reserved_tokens depleted: reserved_tokens=" << reserved_tokens_
                                              << " used=" << tokens_used_->prompt_tokens_used_ << "+"
                                              << tokens_used_->completion_tokens_used_));
    }
  }
}

void ProxyRunningRequest::receive_answer_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerError> ans) {
  if (sent_answer_) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "out of order answer parts"));
    return;
  }

  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received error";
  fail(td::Status::Error(ans->error_code_, ans->error_));
}

void ProxyRunningRequest::receive_answer_part(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPart> ans) {
  if (!sent_answer_) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "out of order answer parts"));
    return;
  }

  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received payload part";

  stats()->answer_bytes_sent += (double)ans->answer_.size();
  payload_parts_++;
  payload_bytes_ += ans->answer_.size();

  tokens_used_ = std::move(ans->tokens_used_);
  auto res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerPart>(
      std::move(ans->answer_), ans->is_completed_, client_request_id_, tokens_used());
  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));
  if (ans->is_completed_) {
    finish(true);
  } else {
    if (tokens_used_->total_tokens_used_ > reserved_tokens_) {
      return fail(td::Status::Error(ton::ErrorCode::error,
                                    PSTRING() << "reserved_tokens depleted: reserved_tokens=" << reserved_tokens_
                                              << " used=" << tokens_used_->prompt_tokens_used_ << "+"
                                              << tokens_used_->completion_tokens_used_));
    }
  }
}

void ProxyRunningRequest::receive_answer_part_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPartError> ans) {
  if (!sent_answer_) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "out of order answer parts"));
    return;
  }

  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received error";
  fail(td::Status::Error(ans->error_code_, ans->error_));
}

void ProxyRunningRequest::fail(td::Status error) {
  LOG(WARNING) << "proxy request " << id_.to_hex() << " is failed: " << error;
  td::BufferSlice res;
  if (!sent_answer_) {
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerError>(error.code(), error.message().str(),
                                                                                  client_request_id_, tokens_used());
  } else {
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerPartError>(
        error.code(), error.message().str(), client_request_id_, tokens_used());
  }
  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));
  finish(false);
}

void ProxyRunningRequest::finish(bool is_success) {
  LOG(INFO) << "proxy request " << id_.to_hex() << ": completed: success=" << (is_success ? "YES" : "NO")
            << " time=" << run_time() << " payload_parts=" << payload_parts_ << " payload_bytes=" << payload_bytes_
            << " tokens_used=" << tokens_used_->prompt_tokens_used_ << "+" << tokens_used_->cached_tokens_used_ << "+"
            << tokens_used_->completion_tokens_used_ << "+" << tokens_used_->reasoning_tokens_used_ << "="
            << tokens_used_->total_tokens_used_;
  if (is_success) {
    stats()->requests_success++;
  } else {
    stats()->requests_failed++;
  }

  auto work_time = run_time();
  stats_->total_requests_time += work_time;

  td::actor::send_closure(runner_, &ProxyRunner::finish_request, id_, client_request_id_, client_,
                          client_connection_id_, worker_->info, worker_, std::move(tokens_used_), reserved_tokens_,
                          is_success, work_time);
  stop();
}

}  // namespace cocoon
