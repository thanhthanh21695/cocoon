#include "WorkerProxyInfo.h"
#include "WorkerRunner.h"
#include "td/utils/port/Clocks.h"
#include <memory>

namespace cocoon {

WorkerProxyInfo::WorkerProxyInfo(WorkerRunner *runner, const td::Bits256 &proxy_public_key,
                                 const block::StdAddress &proxy_sc_address) {
  sc_ = std::make_shared<WorkerContract>(runner->owner_address(), proxy_sc_address, proxy_public_key, runner,
                                         runner->runner_config());
  sc_->subscribe_to_updates(sc_);
  class Cb : public WorkerContract::Callback {
   public:
    Cb(WorkerProxyInfo *self) : self_(self) {
    }
    void on_transaction(const block::StdAddress &src_address, td::uint32 op, td::uint64 qid) override {
      self_->sc_request_completed(src_address, op, qid);
    }

   private:
    WorkerProxyInfo *self_;
  };
  sc_->set_callback(std::make_unique<Cb>(this));
  sc_->deploy([](td::Result<td::Unit> R) {
    if (R.is_error()) {
      LOG(FATAL) << "failed to deploy worker sc: " << R.move_as_error();
    }
  });
}

bool WorkerProxyInfo::update_payment_info(const cocoon_api::proxy_signedPayment &payment) {
  auto R = sc_->check_signed_pay_message(payment.data_.as_slice());
  if (R.is_error()) {
    LOG(ERROR) << "received bad payment message: " << R.move_as_error();
    return false;
  }
  auto tokens = R.move_as_ok();
  if (tokens > tokens_committed_to_blockchain_) {
    tokens_committed_to_blockchain_ = tokens;
    payout_message_ = td::UniqueSlice(payment.data_.as_slice());
    update_tokens_committed_to_proxy_db(tokens);
  }
  return tokens == tokens_committed_to_blockchain_;
}

void WorkerProxyInfo::store_stats(td::StringBuilder &sb) {
  sb << "<table>\n";
  sb << "<tr><td>sc inited</td><td>" << (is_inited() ? "YES" : "NO") << "</td></tr>\n";
  sb << "<tr><td>proxy sc address</td><td>" << sc()->runner()->address_link(proxy_sc_address()) << "</td></tr>\n";
  sb << "<tr><td>proxy public key</td><td>" << proxy_public_key().to_hex() << "</td></tr>\n";
  sb << "<tr><td>sc address</td><td>" << sc()->runner()->address_link(worker_sc_address()) << "</td></tr>\n";
  sb << "<tr><td>earned tokens</td><td>" << earned_tokens_committed_to_blockchain() << "/"
     << earned_tokens_committed_to_proxy_db() << "/" << earned_tokens_max_known() << " (~"
     << to_ton(earned_tokens_committed_to_blockchain() *
               sc()->runner_config()->root_contract_config->worker_fee_per_token())
     << " TON)"
     << "</td></tr>\n";
  sb << "<tr><td>tokens cashed out</td><td>" << tokens_cashed_out() << "</td></tr>\n";
  sb << "<tr><td>expected tokens cashed out</td><td>" << exp_tokens_cashed_out() << "</td></tr>\n";
  sb << "<tr><td>gained</td><td>" << to_payout() << " (~"
     << to_ton(to_payout() * sc()->runner_config()->root_contract_config->worker_fee_per_token()) << " TON)";
  if (to_payout() > 0) {
    sb << " <a href=\"/request/payout?proxy=" << proxy_sc_address().rserialize(true) << "\">take now</a>";
  }
  sb << "</td></tr>\n";
  sb << "<tr><td>running request</td><td>" << (sc_request_is_running() ? "YES" : "NO") << "</td></tr>\n";
  sb << "<tr><td>params version</td><td>" << sc()->runner_config()->root_contract_config->params_version()
     << "</td></tr>\n";
  sb << "</table>\n";
}

void WorkerProxyInfo::store_stats(SimpleJsonSerializer &jb) {
  jb.start_object();
  jb.add_element("sc_inited", is_inited());
  jb.add_element("proxy_sc_address", proxy_sc_address().rserialize(true));
  jb.add_element("proxy_public_key", proxy_public_key().to_hex());
  jb.add_element("sc_address", worker_sc_address().rserialize(true));
  jb.add_element("earned_tokens_committed_to_blockchain", earned_tokens_committed_to_blockchain());
  jb.add_element("earned_tokens_committed_to_proxy_db", earned_tokens_committed_to_proxy_db());
  jb.add_element("earned_tokens_max_known", earned_tokens_max_known());
  jb.add_element("cached_out_tokens", tokens_cashed_out());
  jb.add_element("expected_cached_out_tokens", exp_tokens_cashed_out());
  jb.add_element("running_request", sc_request_is_running());
  jb.add_element("params_version", sc()->runner_config()->root_contract_config->params_version());
  jb.stop_object();
}

ClientCheckResult WorkerProxyInfo::check() {
  CHECK(sc_);
  auto runner = static_cast<WorkerRunner *>(sc_->runner());
  if (sc_request_is_running() || !is_inited() || !is_started()) {
    return ClientCheckResult::Ok;
  }

  if (is_closed()) {
    return ClientCheckResult::Delete;
  }

  /* if request_is_running() == false we can assume, that exp_sc_tokens_processed has the correct value */
  auto delta = to_payout();

  bool is_outdated = sc()->runner_config()->root_contract_config->params_version() <
                     runner->runner_config()->root_contract_config->params_version();

  if (is_outdated) {
    auto waiting_for = time_since_close_started();
    /* need close, but waiting for proxy to do it. But also should try to get money before clients */
    if (waiting_for < 0.5 * sc()->runner_config()->root_contract_config->client_delay_before_close()) {
      return ClientCheckResult::Ok;
    }

    /* we waited long enough. we should assume, that proxy sent everything it wanted */

    /* balance is so low, that we don't want to bother */
    if (delta < runner->min_worker_payout_sum_on_close()) {
      return ClientCheckResult::Delete;
    }

    runner->proxy_request_payout(*this);

    return ClientCheckResult::Ok;
  }

  if (delta >= runner->min_worker_payout_sum()) {
    runner->proxy_request_payout(*this);

    return ClientCheckResult::Ok;
  }

  auto r = td::Clocks::monotonic() - last_request_at_;
  if (r > 0 && delta >= runner->min_worker_payout_sum_on_idle()) {
    runner->proxy_request_payout(*this);

    return ClientCheckResult::Ok;
  }

  /* nothing to do */
  return ClientCheckResult::Ok;
}

}  // namespace cocoon
