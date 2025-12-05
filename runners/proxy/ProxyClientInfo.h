#pragma once

#include "ProxySignedPayments.hpp"
#include "runners/BaseRunner.hpp"
#include <algorithm>
#include <limits>
#include <memory>

namespace cocoon {

class ProxyRunner;

class ProxyClientInfo : public std::enable_shared_from_this<ProxyClientInfo> {
 public:
  ProxyClientInfo(ProxyRunner *runner, const block::StdAddress &client_owner_address,
                  std::shared_ptr<RunnerConfig> runner_config);

  ProxyClientInfo(ProxyRunner *runner, const cocoon_api::proxyDb_ClientInfo &c,
                  std::shared_ptr<RunnerConfig> runner_config);

  std::shared_ptr<ProxyClientInfo> shared_ptr() {
    return shared_from_this();
  }

  const auto &client_owner_address() const {
    return client_owner_address_;
  }
  const auto &client_sc_address() const {
    return client_sc_address_;
  }
  bool allow_queries() const {
    return sc_status_ == 0;
  }
  bool charging_now() const {
    return charging_now_;
  }
  bool is_closed() const {
    return sc_status_ == 2;
  }
  bool is_closing() const {
    return sc_status_ == 1;
  }
  bool exp_is_closed() const {
    return exp_sc_closed_;
  }
  auto running_queries() const {
    return running_queries_;
  }
  auto tokens_committed_to_blockchain() const {
    return signed_payments_.tokens_committed_to_blockchain();
  }
  auto tokens_committed_to_db() const {
    return signed_payments_.tokens_committed_to_db();
  }
  auto tokens_max() const {
    return signed_payments_.tokens_max();
  }
  auto tokens_used() const {
    return signed_payments_.tokens_max();
  }
  bool has_signed_payment() const {
    return signed_payments_.has_signed_payment();
  }
  td::Slice signed_payment_data() const {
    return signed_payments_.signed_payment_data();
  }
  auto signed_payment_tokens() const {
    return signed_payments_.tokens_committed_to_blockchain();
  }
  ton::tl_object_ptr<cocoon_api::proxy_SignedPayment> signed_payment() const {
    if (has_signed_payment()) {
      return create_tl_object<cocoon_api::proxy_signedPayment>(td::BufferSlice(signed_payment_data()));
    } else {
      return create_tl_object<cocoon_api::proxy_signedPaymentEmpty>();
    }
  }
  auto tokens_ready_to_charge() const {
    return std::max<td::int64>(0, tokens_committed_to_blockchain() - exp_sc_tokens_used_);
  }
  auto tokens_max_to_charge() const {
    return tokens_max() - sc_tokens_used_;
  }
  auto tokens_available() const {
    auto max_allowed_tokens = std::min(sc_tokens_payed_, sc_tokens_stake_ + sc_tokens_used_);
    return max_allowed_tokens - tokens_reserved_ - tokens_used();
  }
  const auto &secret_hash() const {
    return sc_secret_hash_;
  }
  auto tokens_payed() const {
    return sc_tokens_payed_;
  }
  auto stake() const {
    return sc_stake_;
  }
  auto tokens_stake() const {
    return sc_tokens_stake_;
  }
  auto tokens_reserved() const {
    return tokens_reserved_;
  }
  bool need_to_write() const {
    return updated_from_db_;
  }
  ton::tl_object_ptr<cocoon_api::proxyDb_ClientInfo> serialize() const {
    return cocoon::create_tl_object<cocoon_api::proxyDb_clientInfoV2>(
        client_owner_address_.rserialize(true), client_sc_address_.rserialize(true), sc_status_, sc_balance_, sc_stake_,
        sc_tokens_used_, tokens_used(), sc_secret_hash_, last_request_at_);
  }
  ton::tl_object_ptr<cocoon_api::client_paymentStatus> serialize_payment_status();

  void update_state(td::int32 state, td::int64 new_balance, td::int64 new_stake, td::int64 new_tokens_used,
                    td::int64 price_per_token, const td::Bits256 &secret_hash) {
    if (new_tokens_used < sc_tokens_used_) {
      return;
    }
    sc_status_ = state;
    update_balance(new_balance, new_tokens_used, price_per_token);
    sc_stake_ = new_stake;
    sc_tokens_stake_ = safe_div(new_stake, price_per_token);
    sc_secret_hash_ = secret_hash;
    updated_from_db_ = true;
  }

  void update_balance(td::int64 new_balance, td::int64 new_tokens_used, td::int64 price_per_token) {
    if (new_tokens_used < sc_tokens_used_) {
      return;
    }
    sc_balance_ = new_balance;
    sc_tokens_payed_ = safe_div(sc_balance_, price_per_token) + new_tokens_used;
    sc_tokens_used_ = new_tokens_used;
    CHECK(sc_tokens_used_ <= tokens_used());
    if (exp_sc_tokens_used_ < sc_tokens_used_) {
      exp_sc_tokens_used_ = sc_tokens_used_;
    }
  }

  void update_signed_payment_data(td::int64 tokens, td::UniqueSlice data) {
    signed_payments_.set_signed_payment(tokens, std::move(data));
  }

  void committed_to_db(td::int32 seqno) {
    signed_payments_.committed_to_db(seqno);
  }

  void committed_to_blockchain(td::int32 seqno) {
    signed_payments_.committed_to_blockchain(seqno);
  }

  bool reserve(td::int64 tokens) {
    if (tokens <= tokens_available()) {
      tokens_reserved_ += tokens;
      return true;
    } else {
      return false;
    }
  }
  void deduct(td::int64 tokens) {
    signed_payments_.incr_tokens(tokens);
    updated_from_db_ = true;
  }
  void release_reserve(td::int64 tokens) {
    tokens_reserved_ -= tokens;
    CHECK(tokens_reserved_ >= 0);
  }
  void charge(td::int64 tokens, bool close) {
    charging_now_ = true;
    exp_sc_tokens_used_ = tokens;
    if (close) {
      exp_sc_closed_ = close;
    }
  }

  void pseudo_initialize() {
    sc_status_ = 0;
    sc_stake_ = to_nano(1e6);
    update_balance(to_nano(1e6), 0, 1);
  }

  void start_query() {
    running_queries_++;
  }
  void stop_query() {
    running_queries_--;
  }

  void charging_completed() {
    charging_now_ = false;
  }

  void written_to_db() {
    updated_from_db_ = false;
  }

  void store_stats(td::StringBuilder &sb, td::int64 price_per_token);
  void store_stats(SimpleJsonSerializer &jb);

  ClientCheckResult check();

 private:
  ProxyRunner *runner_;
  block::StdAddress client_owner_address_;
  block::StdAddress client_sc_address_;
  td::uint32 sc_status_{3};
  td::int64 sc_balance_{0};
  td::int64 sc_tokens_used_{0};
  td::int64 sc_stake_{to_nano(1.0)};
  td::int64 sc_tokens_stake_{0};
  td::int64 sc_tokens_payed_{0};
  td::Bits256 sc_secret_hash_ = td::Bits256::zero();

  td::int64 exp_sc_tokens_used_{0};
  bool exp_sc_closed_{false};
  bool charging_now_{false};

  td::int64 tokens_reserved_{0};

  td::int64 running_queries_{0};
  td::int32 last_request_at_{0};

  ProxySignedPayments signed_payments_;

  bool updated_from_db_{true};
};

}  // namespace cocoon
