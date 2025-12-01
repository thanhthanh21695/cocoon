#pragma once

#include "auto/tl/cocoon_api.h"
#include "common/bitstring.h"
#include "runners/BaseRunner.hpp"
#include "ProxyWorkerConnectionInfo.h"
#include "ProxyInboundConnection.h"
#include "ProxyRunningRequest.hpp"
#include "OldProxyContract.hpp"
#include "td/actor/ActorId.h"
#include "runners/smartcontracts/ProxyContract.hpp"
#include "tl/TlObject.h"
#include "ton/ton-types.h"
#include <memory>

namespace cocoon {

struct WorkerModel {
  std::string model_base_name;
  std::map<TcpClient::ConnectionId, std::shared_ptr<ProxyWorkerConnectionInfo>> connections;
};

class ProxyRunner : public BaseRunner {
 public:
  ProxyRunner(std::string engine_config_filename) : BaseRunner(std::move(engine_config_filename)) {
  }

  /* CONST PARAMS */
  static constexpr td::int64 min_client_charge_sum() {
    return to_nano(1);
  }
  static constexpr td::int64 min_client_charge_sum_on_close() {
    return to_nano(0.2);
  }
  static constexpr td::int64 min_worker_payout_sum() {
    return to_nano(10);
  }
  static constexpr td::int64 min_worker_payout_sum_on_close() {
    return to_nano(0.2);
  }

  /* SIMPLE GETTERS */
  const auto &owner_address() const {
    return owner_address_;
  }
  const auto &public_key() const {
    return public_key_;
  }
  block::StdAddress cur_sc_address() {
    return sc_->address();
  }
  block::StdAddress sc_address(const std::shared_ptr<RunnerConfig> config);
  td::int64 price_per_token() const {
    return sc_ ? sc_->price_per_token() : 0;
  }
  td::int64 worker_fee_per_token() const {
    return sc_ ? sc_->worker_fee_per_token() : 0;
  }
  auto last_saved_state_seqno() const {
    return last_saved_state_seqno_;
  }
  auto active_config_version() const {
    return active_config_version_;
  }
  bool check_worker_hashes() const {
    return check_worker_hashes_;
  }
  const auto &sc() const {
    return sc_;
  }
  bool is_disabled() const {
    return sc_ == nullptr;
  }

  /* SIMPLE SETTERS */
  void enable_check_worker_hashes() {
    check_worker_hashes_ = true;
  }
  void set_owner_address(block::StdAddress owner_address) {
    owner_address_ = std::move(owner_address);
  }

  /* WORKER */
  td::Result<std::shared_ptr<ProxyWorkerInfo>> register_worker(const block::StdAddress &worker_owner_address);
  td::Result<std::shared_ptr<ProxyWorkerConnectionInfo>> register_worker_connection(
      std::shared_ptr<ProxyWorkerInfo> worker, TcpClient::ConnectionId connection_id, const td::Bits256 &worker_hash,
      std::string model, td::int32 coefficient, td::int32 max_active_requests);
  void unregister_worker_connection(std::shared_ptr<ProxyWorkerConnectionInfo> worker_connection_info);
  void sign_worker_payment(ProxyWorkerInfo &w);
  void on_worker_update(const block::StdAddress &worker_owner_address, const block::StdAddress &worker_sc_address,
                        td::uint32 state, td::int64 tokens);
  void worker_payout(ProxyWorkerInfo &worker, bool force_close);
  void worker_payout_completed(std::shared_ptr<ProxyWorkerInfo> worker, td::int64 tokens);

  /* CLIENT */
  std::shared_ptr<ProxyClientInfo> get_client(const std::string &client_owner_address_str);
  td::Result<std::shared_ptr<ProxyClientInfo>> register_client(const block::StdAddress &client_owner_address);
  td::Result<std::shared_ptr<ProxyConnectingClient>> register_connecting_client(
      const block::StdAddress &client_owner_address, TcpClient::ConnectionId connection_id);
  void unregister_connecting_client(td::uint64 nonce);
  void sign_client_payment(ProxyClientInfo &w);
  void client_charge(ProxyClientInfo &client, bool force_close);
  void client_charge_completed(std::shared_ptr<ProxyClientInfo> client, td::int64 tokens);
  void update_client_information(const block::StdAddress &owner_address, td::int64 balance, td::int64 tokens_used) {
    auto owner_str = owner_address.rserialize(true);
    auto it = clients_.find(owner_str);
    if (it != clients_.end()) {
      it->second->update_balance(balance, tokens_used, price_per_token());
    }
  }
  void on_client_update(const block::StdAddress &client_owner_address, const block::StdAddress &client_sc_address,
                        td::uint32 state, td::int64 new_balance, td::int64 new_stake, td::int64 tokens_used,
                        const td::Bits256 &secret_hash);
  void on_client_register(const block::StdAddress &client_owner_address, const block::StdAddress &client_sc_address,
                          td::uint64 nonce);

  /* ALLOCATORS */
  std::unique_ptr<BaseInboundConnection> allocate_inbound_connection(TcpClient::ConnectionId connection_id,
                                                                     TcpClient::ListeningSocketId listening_socket_id,
                                                                     const RemoteAppType &remote_app_type,
                                                                     const td::Bits256 &remote_app_hash) override;

  /* INITIALIZATION */
  void load_config(td::Promise<td::Unit> promise) override;
  void custom_initialize(td::Promise<td::Unit> promise) override;
  void initialize_sc(std::shared_ptr<RunnerConfig> snapshot_runner_config, const ton::BlockIdExt &init_block_id,
                     td::Promise<td::Unit> promise);
  void deploy_proxy_sc(std::string sc_address, td::Promise<td::Unit> promise);
  void wait_sync_proxy_sc(std::string sc_address, td::Promise<td::Unit> promise);

  /* DB */
  void on_receive_saved_state_seqno(td::int32 seqno, const td::Bits256 &unique_hash);
  void process_db_key(td::Slice key, td::Slice value, std::shared_ptr<RunnerConfig> runner_config);
  void client_to_db(ProxyClientInfo &client);
  void worker_to_db(ProxyWorkerInfo &client);
  void config_to_db(std::shared_ptr<RunnerConfig> config);
  void all_to_db();
  td::UniqueSlice get_from_db(td::Slice key);
  void set_to_db(td::Slice key, td::Slice value);
  void del_from_db(td::Slice key) {
    kv_->erase(key).ensure();
  }
  void flush_db() {
    kv_->flush().ensure();
  }
  template <typename F>
  void db_transaction(F &&run) {
    kv_->begin_transaction();
    run();
    kv_->commit_transaction();
  }
  void save_state_to_blockchain_completed(td::int32 seqno);

  /* CRON */
  void alarm() override;
  void close_all();
  void on_root_contract_config_update(std::shared_ptr<RunnerConfig> config);

  /* INBOUND MESSAGE HANDLERS */
  void receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) override;
  void receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice query,
                     td::Promise<td::BufferSlice> promise) override;
  void receive_http_request(
      std::unique_ptr<ton::http::HttpRequest> request, std::shared_ptr<ton::http::HttpPayload> payload,
      td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise)
      override;

  /* CONTROL */
  void proxy_enable_disable(td::int64 value);

  /* REQUEST HANDLING */
  td::Result<std::shared_ptr<ProxyWorkerConnectionInfo>> choose_connection(const std::string &model_name,
                                                                           td::int64 tokens_available,
                                                                           td::int64 max_coefficient,
                                                                           td::int64 max_tokens);
  void forward_query(TcpClient::ConnectionId client_connection_id, ton::tl_object_ptr<cocoon_api::client_runQuery> req);
  void finish_request(const td::Bits256 &worker_request_id, const td::Bits256 &client_request_id,
                      std::shared_ptr<ProxyClientInfo> client, TcpClient::ConnectionId client_connection_id,
                      std::shared_ptr<ProxyWorkerInfo> worker,
                      std::shared_ptr<ProxyWorkerConnectionInfo> worker_connection,
                      ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used, td::int64 to_unlock, bool is_success,
                      double work_time);

  /* UTILS */

  td::Ref<vm::Cell> sign_and_wrap_message(td::Ref<vm::Cell> msg, const block::StdAddress &return_excesses_to) {
    return BaseRunner::sign_and_wrap_message(*private_key_, std::move(msg), return_excesses_to);
  }

  void withdraw_completed() {
    running_withdraw_ = false;
  }

  /* HTTP HANDLING */

  std::string wrap_short_answer_to_http(std::string text) {
    td::StringBuilder sb;
    sb << "<!DOCTYPE html>\n";
    sb << "<html><body>\n";
    sb << text << "<br/>\n";
    sb << "<a href=\"/stats\">return to stats</a>\n";
    sb << "</html></body>\n";
    return sb.as_cslice().str();
  };
  std::string http_generate_main();
  std::string http_generate_json_stats();
  std::string http_payout(std::string worker_sc_address);
  std::string http_charge(std::string client_sc_address);
  std::string http_enable_disable(td::int64 disable_up_to_version);
  std::string http_withdraw();

 private:
  block::StdAddress owner_address_;
  std::map<std::string, std::shared_ptr<ProxyClientInfo>> clients_;
  std::map<std::string, std::shared_ptr<ProxyWorkerInfo>> workers_;
  std::map<std::string, WorkerModel> models_;
  std::map<td::uint64, std::shared_ptr<ProxyConnectingClient>> connecting_clients_;
  std::map<td::Bits256, td::actor::ActorId<ProxyRunningRequest>> running_queries_;

  std::unique_ptr<td::Ed25519::PrivateKey> private_key_;
  std::unique_ptr<td::Ed25519::PublicKey> public_key_obj_;
  td::Bits256 public_key_;

  std::unique_ptr<td::Ed25519::PrivateKey> wallet_private_key_;
  td::Bits256 wallet_public_key_;

  std::shared_ptr<ProxyContract> sc_;
  bool sent_sc_init_message_{false};
  td::int64 is_disabled_until_version_{0};

  bool generate_random_private_key_{false};
  bool check_worker_hashes_{false};
  bool running_withdraw_{false};
  bool running_save_state_to_blockchain_{false};
  bool sc_is_initializing_{false};

  std::string db_path_;
  td::Timestamp next_db_flush_at_;
  std::shared_ptr<td::KeyValue> kv_;

  td::Bits256 local_image_hash_unverified_;

  td::uint32 active_config_version_{0};

  std::map<std::string, std::shared_ptr<OldProxyContract>> old_proxy_contracts_;
  std::shared_ptr<ProxyStats> stats_ = std::make_shared<ProxyStats>();

  td::Timestamp next_db_save_to_blockchain_at_;
  td::int32 first_saved_state_seqno_{0};
  td::int32 last_saved_state_seqno_{0};
  td::int32 last_received_saved_state_seqno_{0};
  td::Bits256 session_unique_hash_;
  td::Promise<td::Unit> session_start_promise_;

  std::map<td::uint32, td::Bits256> pending_blockchain_seqno_commits_;
};

}  // namespace cocoon
