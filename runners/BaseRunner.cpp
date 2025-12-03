#include "Ed25519.h"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/tonlib_api.h"
#include "auto/tl/tonlib_api.hpp"
#include "block.h"
#include "cocoon/tdx.h"
#include "common/bitstring.h"
#include "http/http.h"
#include "net/TcpClient.h"
#include "td/actor/ActorId.h"
#include "td/actor/ActorOwn.h"
#include "td/actor/MultiPromise.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/UInt.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/signals.h"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"

#include "BaseRunner.hpp"
#include "runners/smartcontracts/ClientContract.hpp"
#include "runners/smartcontracts/ProxyContract.hpp"
#include "runners/smartcontracts/WorkerContract.hpp"

#include "common/errorcode.h"
#include "cocoon-tl-utils/parsers.hpp"
#include "crypto/common/refcnt.hpp"
#include "td/actor/ActorStats.h"
#include "td/actor/coro_utils.h"
#include "td/utils/port/path.h"
#include "tl/TlObject.h"
#include "tonlib/tonlib/TonlibCallback.h"
#include "tonlib/tonlib/TonlibClient.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include <atomic>
#include <cmath>
#include <ctime>
#include <iostream>
#include <memory>
#include <utility>

namespace cocoon {

/* 
 *
 * REMOTE APP TYPE
 *
 */

RemoteAppType remote_app_type_proxy() {
  RemoteAppType t;
  t.info = "proxy";
  return t;
}

RemoteAppType remote_app_type_unknown() {
  RemoteAppType t;
  t.info = "";
  return t;
}

RemoteAppType remote_app_type_worker() {
  RemoteAppType t;
  t.info = "worker";
  return t;
}

/*
 *
 * BASE CONNECTION
 *
 */

void BaseConnection::close_connection() {
  if (status_ != BaseConnectionStatus::Closing) {
    status_ = BaseConnectionStatus::Closing;
    pre_close();
    last_status_change_at_ = td::Timestamp::now();
    td::actor::send_closure(runner_->tcp_client(), &TcpClient::fail_connection, connection_id_);
  }
}

/*
 *
 * PROXY OUTBOUND CONNECTION 
 *
 */
void ProxyOutboundConnection::post_ready() {
  runner()->proxy_connection_is_ready(connection_id(), proxy_target_id());
}

/*
 *
 * PROXY TARGET
 *
 */

void ProxyTarget::connected(TcpClient::ConnectionId connection_id) {
  if (connection_id_ == connection_id) {
    return;
  }
  close_connection();
  connection_id_ = connection_id;
  switch (status_) {
    case ProxyTargetStatus::Connecting:
      status_ = ProxyTargetStatus::RunningInitialHandshake;
      last_status_change_at_ = td::Timestamp::now();
      break;
    case ProxyTargetStatus::RunningInitialHandshake:
      break;
    case ProxyTargetStatus::Reconnecting:
      status_ = ProxyTargetStatus::RunningReconnectHandshake;
      last_status_change_at_ = td::Timestamp::now();
      break;
    case ProxyTargetStatus::RunningReconnectHandshake:
      break;
    case ProxyTargetStatus::Ready:
      break;
  }
}

void ProxyTarget::connection_is_ready(TcpClient::ConnectionId connection_id) {
  if (connection_id_ != connection_id) {
    return;
  }

  if (status_ != ProxyTargetStatus::Ready) {
    status_ = ProxyTargetStatus::Ready;
    last_status_change_at_ = td::Timestamp::now();
  }
}

void ProxyTarget::disconnected(TcpClient::ConnectionId connection_id) {
  if (connection_id != connection_id_) {
    return;
  }

  connection_id_ = 0;

  switch (status_) {
    case ProxyTargetStatus::Connecting:
      break;
    case ProxyTargetStatus::RunningInitialHandshake:
      status_ = ProxyTargetStatus::Connecting;
      last_status_change_at_ = td::Timestamp::now();
      break;
    case ProxyTargetStatus::Reconnecting:
      break;
    case ProxyTargetStatus::RunningReconnectHandshake:
      status_ = ProxyTargetStatus::Reconnecting;
      last_status_change_at_ = td::Timestamp::now();
      break;
    case ProxyTargetStatus::Ready:
      status_ = ProxyTargetStatus::Reconnecting;
      last_status_change_at_ = td::Timestamp::now();
      last_ready_at_ = td::Timestamp::now();
      break;
  }
}

void ProxyTarget::close_connection() {
  if (connection_id_) {
    runner()->close_connection(connection_id_);
  }
}

bool ProxyTarget::should_choose_another_proxy() {
  if (is_ready()) {
    return false;
  }
  if (status_ == ProxyTargetStatus::Connecting || status_ == ProxyTargetStatus::Reconnecting) {
    return last_ready_at_.in() <= -300;
  }
  if (status_ == ProxyTargetStatus::RunningInitialHandshake ||
      status_ == ProxyTargetStatus::RunningReconnectHandshake) {
    return last_ready_at_.in() <= -300;
  }
  return false;
}

/* 
 *
 * BASE RUNNER 
 *
 */

/*
 *
 * SETTERS
 *
 */
void BaseRunner::set_root_contract_config(std::shared_ptr<RootContractConfig> config, int ts) {
  auto conf = std::make_shared<RunnerConfig>();
  conf->root_contract_config = std::move(config);
  conf->root_contract_ts = ts;
  conf->ton_disabled = ton_disabled_;
  conf->is_testnet = is_testnet_;
  runner_config_ = std::move(conf);
}

td::Status BaseRunner::connection_to_proxy_via(td::Slice addr) {
  auto p = addr.find(':');
  if (p == td::Slice::npos) {
    return td::Status::Error("expected <ip>:<port>");
  }

  TRY_RESULT(port, td::to_integer_safe<td::uint16>(addr.copy().remove_prefix(p + 1)));

  td::IPAddress a;
  TRY_STATUS(a.init_ipv4_port(addr.truncate(p).str(), port));

  connection_to_proxy_via_ = a;

  return td::Status::OK();
}

/* 
 *
 * INITIALIZATION
 *
 */
void BaseRunner::start_up() {
  alarm_timestamp() = td::Timestamp::in(td::Random::fast(1.0, 2.0));
  actor_stats_ = td::actor::create_actor<td::actor::ActorStats>("ActorStats");
}

void BaseRunner::initialize() {
  load_config([self_id = actor_id(this)](td::Result<td::Unit> R) {
    if (R.is_error()) {
      td::actor::send_closure(self_id, &BaseRunner::initialization_failure,
                              R.move_as_error_prefix("failed to parse runner config: "));
    } else {
      td::actor::send_closure(self_id, &BaseRunner::load_config_completed);
    }
  });
}
void BaseRunner::load_config(td::Promise<td::Unit> promise) {
  promise.set_value(td::Unit());
}
void BaseRunner::load_config_completed() {
  initialize_http_server([self_id = actor_id(this)](td::Result<td::Unit> R) {
    if (R.is_error()) {
      td::actor::send_closure(self_id, &BaseRunner::initialization_failure,
                              R.move_as_error_prefix("failed initalize http server: "));
    } else {
      td::actor::send_closure(self_id, &BaseRunner::http_server_initialized);
    }
  });
}
void BaseRunner::initialize_http_server(td::Promise<td::Unit> promise) {
  if (http_port_ > 0) {
    class Cb : public ton::http::HttpServer::Callback {
     public:
      Cb(td::actor::ActorId<BaseRunner> client) : client_(std::move(client)) {
      }

      void receive_request(
          std::unique_ptr<ton::http::HttpRequest> request, std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) override {
        td::actor::send_closure(client_, &BaseRunner::receive_http_request_outer, std::move(request),
                                std::move(payload), std::move(promise));
      }

     private:
      td::actor::ActorId<BaseRunner> client_;
    };
    http_server_ = ton::http::HttpServer::create(http_port_, std::make_unique<Cb>(actor_id(this)));
  }
  promise.set_value(td::Unit());
}
void BaseRunner::http_server_initialized() {
  initialize_rpc_server([self_id = actor_id(this)](td::Result<td::Unit> R) {
    if (R.is_error()) {
      td::actor::send_closure(self_id, &BaseRunner::initialization_failure,
                              R.move_as_error_prefix("failed to initialize rpc server: "));
    } else {
      td::actor::send_closure(self_id, &BaseRunner::rpc_server_initialized);
    }
  });
}
void BaseRunner::initialize_rpc_server(td::Promise<td::Unit> promise) {
  client_ = TcpClient::create(make_tcp_client_callback());
  for (auto &x : rpc_ports_) {
    td::actor::send_closure(client_, &TcpClient::add_listening_port, generate_unique_uint64(), x.first, x.second);
  }

  if (connection_to_proxy_via_.is_valid()) {
    LOG(INFO) << "using proxy " << connection_to_proxy_via_;
    td::actor::send_closure(client_, &TcpClient::add_connection_to_remote_app_type_rule, remote_app_type_proxy(),
                            std::make_shared<TcpConnectionType>(TcpConnectionSocks5(connection_to_proxy_via_)));
  } else {
    LOG(INFO) << "using " << (fake_tdx_ ? "fake" : "real") << " tdx-tls connection";
    auto cert_and_key = tdx::generate_cert_and_key(nullptr);
    auto tdx_interface = fake_tdx_ ? tdx::TdxInterface::create_fake() : tdx::TdxInterface::create();
    tdx::PolicyConfig conf{};  // allow all
    auto policy = tdx::Policy::make(tdx_interface, conf);
    td::actor::send_closure(client_, &TcpClient::add_connection_to_remote_app_type_rule, remote_app_type_proxy(),
                            std::make_shared<TcpConnectionType>(TcpConnectionTls(cert_and_key, policy)));
  }
  promise.set_value(td::Unit());
}
void BaseRunner::rpc_server_initialized() {
  coro_init().start().detach("BaseRunner::coro_init");
}

td::actor::Task<td::Unit> BaseRunner::try_run_initialization_task(td::Slice name, td::actor::Task<td::Unit> task) {
  auto r = co_await std::move(task).wrap();
  if (r.is_error()) {
    initialization_failure(r.move_as_error_prefix(PSLICE() << "failed to " << name << ": "));
    co_return td::Status::Error("Unreachable");
  }
  co_return td::Unit{};
}
td::actor::Task<td::Unit> BaseRunner::coro_init() {
  co_await try_run_initialization_task("initialize tonlib", initialize_tonlib());
  co_await try_run_initialization_task("get root smartcontract", get_root_contract_initial_state());
  coro_init_done();
  co_return td::Unit{};
}
td::actor::Task<td::Unit> BaseRunner::initialize_tonlib() {
  if (ton_disabled()) {
    co_return td::Unit();
  }
  co_await tonlib_wrapper_.initialize(ton_config_filename_, is_testnet());
  co_await tonlib_wrapper_.sync();
  set_tonlib_synced();
  co_return td::Unit();
}
td::actor::Task<td::Unit> BaseRunner::get_root_contract_initial_state() {
  if (ton_disabled()) {
    auto config = co_await RootContractConfig::load_from_json(ton_pseudo_config_, is_testnet());
    set_root_contract_config(std::move(config), (int)std::time(0));
    co_return td::Unit{};
  }
  co_await update_root_contract_state();
  co_return td::Unit{};
}
void BaseRunner::coro_init_done() {
  custom_initialize([self_id = actor_id(this)](td::Result<td::Unit> R) {
    if (R.is_error()) {
      td::actor::send_closure(self_id, &BaseRunner::initialization_failure,
                              R.move_as_error_prefix("custom initialize failed: "));
    } else {
      td::actor::send_closure(self_id, &BaseRunner::custom_initialize_completed);
    }
  });
}
void BaseRunner::custom_initialize_completed() {
  initialization_completed();
}
void BaseRunner::initialization_failure(td::Status error) {
  LOG(FATAL) << "failed to initialize: " << error;
}

void BaseRunner::initialization_completed() {
  is_initialized_ = true;
  LOG(INFO) << "initialization completed, running...";
}

/*
 *
 * TONLIB
 *
 */
void BaseRunner::tonlib_do_send_request(ton::tl_object_ptr<ton::tonlib_api::Function> func,
                                        td::Promise<ton::tl_object_ptr<ton::tonlib_api::Object>> cb) {
  connect(std::move(cb), tonlib_wrapper_.request_raw(std::move(func)));
}

void BaseRunner::send_external_message(const block::StdAddress &to, td::Ref<vm::Cell> code, td::Ref<vm::Cell> data,
                                       td::Promise<td::Unit> promise) {
  connect(std::move(promise), send_external_message_coro(to, std::move(code), std::move(data)));
}

td::actor::Task<td::Unit> BaseRunner::send_external_message_coro(const block::StdAddress &to, td::Ref<vm::Cell> code,
                                                                 td::Ref<vm::Cell> data) {
  if (ton_disabled()) {
    co_return td::Unit();
  }
  vm::CellBuilder cb;
  cb.store_long(2, 2);  // ext_in_msg_info
  cb.store_long(0, 2);  // addr_none
  store_address(cb, to);
  store_coins(cb, 0);
  if (code.not_null()) {
    cb.store_bool_bool(true);
    cb.store_bool_bool(true);  // ref
    cb.store_ref(code);
  } else {
    cb.store_bool_bool(false);
  }
  CHECK(data.not_null());
  cb.store_bool_bool(true);  // ref
  cb.store_ref(data);
  auto serialized_boc = vm::std_boc_serialize(cb.finalize()).move_as_ok().as_slice().str();
  auto R = co_await tonlib_wrapper_.request<tonlib_api::raw_sendMessage>(std::move(serialized_boc)).wrap();
  if (R.is_error()) {
    LOG(ERROR) << "tonlib: failed to send external message: " << R.error();
    co_return R.move_as_error();
  }
  co_return td::Unit();
}

/*
 *
 * PROXY TARGET 
 *
 */

void BaseRunner::connect_proxy() {
  LOG(DEBUG) << "connecting to proxy";
  if (!runner_config_) {
    LOG(DEBUG) << "no root contract";
    return;
  }

  auto proxy = runner_config_->root_contract_config->get_random_proxy();
  if (!proxy) {
    LOG(WARNING) << "cannot connection to a proxy: no proxies in root contract";
    return;
  }

  td::IPAddress dst_addr =
      connect_to_proxy_to_client_address_ ? proxy->address_for_clients : proxy->address_for_workers;
  if (get_proxy_target_by_address(dst_addr)) {
    LOG(DEBUG) << "duplicate";
    /* duplicate */
    return;
  }
  auto target_id = generate_unique_uint64();
  auto p = allocate_proxy_target(target_id, dst_addr);
  if (!p) {
    LOG(WARNING) << "cannot allocate proxy target";
    return;
  }
  td::actor::send_closure(client_, &TcpClient::add_outbound_address, target_id, dst_addr, remote_app_type_proxy());
  CHECK(proxy_targets_.emplace(target_id, std::move(p)).second);
  LOG(INFO) << "OK, connecting to " << dst_addr;
}

void BaseRunner::disconnect_proxy(TcpClient::TargetId target_id) {
  LOG(INFO) << "disconnecting from proxy...";
  auto it = proxy_targets_.find(target_id);
  if (it == proxy_targets_.end()) {
    return;
  }

  auto connection_id = it->second->connection_id();
  if (connection_id) {
    close_connection(connection_id);
  }

  proxy_targets_.erase(target_id);
  td::actor::send_closure(client_, &TcpClient::del_outbound_address, target_id);
}

void BaseRunner::cond_reconnect_to_proxy() {
  for (auto &x : proxy_targets_) {
    if (x.second->should_choose_another_proxy()) {
      disconnect_proxy(x.first);
      break;
    }
  }
  if (proxy_targets_.size() < proxy_targets_number_) {
    connect_proxy();
  }
}

/*
 *
 * CONNECTIONS
 *
 */

void BaseRunner::inbound_connection_ready(TcpClient::ConnectionId connection_id,
                                          TcpClient::ListeningSocketId listening_socket_id,
                                          const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash) {
  auto conn = allocate_inbound_connection(connection_id, listening_socket_id, remote_app_type, remote_app_hash);
  if (!conn) {
    close_connection(connection_id);
    return;
  }

  auto it = all_connections_.emplace(connection_id, std::move(conn)).first;
  it->second->start_up();
}

void BaseRunner::outbound_connection_ready(TcpClient::ConnectionId connection_id, TcpClient::TargetId target_id,
                                           const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash) {
  LOG(INFO) << "outbound connection ready: connection_id=" << connection_id << " target_id=" << target_id;
  auto it = proxy_targets_.find(target_id);
  if (it == proxy_targets_.end()) {
    LOG(INFO) << "failing created outbound connection: unknown proxy target " << target_id;
    close_connection(connection_id);
    return;
  }
  auto proxy_conn = allocate_proxy_outbound_connection(connection_id, target_id, remote_app_type, remote_app_hash);
  if (!proxy_conn) {
    LOG(INFO) << "failing created outbound connection: rejected by application";
    close_connection(connection_id);
    return;
  }
  auto it2 = all_connections_.emplace(connection_id, std::move(proxy_conn)).first;

  LOG(DEBUG) << "sending connected to created outbound connection";
  it->second->connected(connection_id);
  it2->second->start_up();
}

void BaseRunner::conn_stop_ready(TcpClient::ConnectionId connection_id) {
  auto it = all_connections_.find(connection_id);
  if (it != all_connections_.end()) {
    it->second->close_connection();
    all_connections_.erase(it);
  }
}

std::unique_ptr<TcpClient::Callback> BaseRunner::make_tcp_client_callback() {
  class Cb : public TcpClient::Callback {
   public:
    Cb(td::actor::ActorId<BaseRunner> runner) : runner_(runner) {
    }
    void on_ready_outbound(TcpClient::ConnectionId connection_id, TcpClient::TargetId target_id,
                           const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash) override {
      td::actor::send_closure(runner_, &BaseRunner::outbound_connection_ready, connection_id, target_id,
                              remote_app_type, remote_app_hash);
    }
    void on_ready_inbound(TcpClient::ConnectionId connection_id, TcpClient::ListeningSocketId listening_socket_id,
                          const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash) override {
      td::actor::send_closure(runner_, &BaseRunner::inbound_connection_ready, connection_id, listening_socket_id,
                              remote_app_type, remote_app_hash);
    }
    void on_stop_ready(TcpClient::ConnectionId connection_id) override {
      td::actor::send_closure(runner_, &BaseRunner::conn_stop_ready, connection_id);
    }
    void receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice message) override {
      td::actor::send_closure(runner_, &BaseRunner::receive_message, connection_id, std::move(message));
    }
    void receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice message,
                       td::Promise<td::BufferSlice> promise) override {
      td::actor::send_closure(runner_, &BaseRunner::receive_query, connection_id, std::move(message),
                              std::move(promise));
    }

   private:
    td::actor::ActorId<BaseRunner> runner_;
  };
  return std::make_unique<Cb>(actor_id(this));
}

/*
 *
 * HANDLERS
 *
 */
void BaseRunner::receive_http_request_outer(
    std::unique_ptr<ton::http::HttpRequest> request, std::shared_ptr<ton::http::HttpPayload> payload,
    td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise) {
  auto R = http_parse_url(request->url());
  if (R.is_error()) {
    ton::http::answer_error(ton::http::HttpStatusCode::status_bad_request, "bad request", std::move(promise));
    return;
  }

  auto info = R.move_as_ok();

  if (info.url == "/perf") {
    connect(std::move(promise), generate_perf_stats(std::move(info)));
    return;
  }

  {
    auto R = http_parse_url(request->url());
    if (R.is_ok()) {
      auto res = R.move_as_ok();
      auto it = custom_http_handlers_.find(res.url);
      if (it != custom_http_handlers_.end()) {
        if (http_access_hash_.size() > 0 && res.get_args["access_hash"] != http_access_hash_) {
          ton::http::answer_error(ton::http::HttpStatusCode::status_bad_request, "bad request", std::move(promise));
          return;
        }
        it->second(res.url, res.get_args, std::move(request), std::move(payload), std::move(promise));
        return;
      }
    }
  }

  receive_http_request(std::move(request), std::move(payload), std::move(promise));
}

void BaseRunner::receive_http_request(
    std::unique_ptr<ton::http::HttpRequest> request, std::shared_ptr<ton::http::HttpPayload> payload,
    td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise) {
  if (payload->payload_type() != ton::http::HttpPayload::PayloadType::pt_empty) {
    ton::http::answer_error(ton::http::HttpStatusCode::status_bad_request, "bad request", std::move(promise));
    return;
  }
  std::string data = "<http><body>OK</body></http>";
  http_send_static_answer(std::move(data), std::move(promise));
}

/*
 *
 * CRON
 *
 */
void BaseRunner::alarm() {
  if (is_initialized()) {
    cond_reconnect_to_proxy();
  }
  while (delayed_action_queue_.size() > 0) {
    const auto &t = delayed_action_queue_.top();
    if (t->is_in_past()) {
      t->run();
      delayed_action_queue_.pop();
    } else {
      break;
    }
  }
  for (auto &m : monitored_accounts_) {
    m->alarm();
  }
  if (next_monitor_at_.is_in_past()) {
    if (!monitored_accounts_update_running_) {
      run_monitor_accounts();
    }
    next_monitor_at_ = td::Timestamp::in(td::Random::fast(5.0, 10.0));
  }
  if (is_initialized() && next_root_contract_state_update_at_.is_in_past() && !root_contract_state_updating_ &&
      !ton_disabled()) {
    next_root_contract_state_update_at_ = td::Timestamp::in(td::Random::fast(30.0, 60.0));
    update_root_contract_state().start().detach("update_root_contract_state");
  }
  alarm_timestamp() = td::Timestamp::in(td::Random::fast(1.0, 2.0));
  alarm_timestamp().relax(next_monitor_at_);
  alarm_timestamp().relax(next_root_contract_state_update_at_);
  if (delayed_action_queue_.size() > 0) {
    alarm_timestamp().relax(delayed_action_queue_.top()->at());
  }
}
td::actor::Task<td::Unit> BaseRunner::update_root_contract_state() {
  root_contract_state_updating_ = true;
  SCOPE_EXIT {
    root_contract_state_updating_ = false;
  };

  auto res = co_await tonlib_wrapper_.request<tonlib_api::raw_getAccountState>(
      ton::create_tl_object<tonlib_api::accountAddress>(root_contract_address_.rserialize(true)));

  LOG(INFO) << "got root contract state with ts=" << res->sync_utime_;

  auto data = res->data_;
  int ts = (td::int32)res->sync_utime_;

  auto cell = co_await vm::std_boc_deserialize(data);

  vm::CellSlice cs{vm::NoVm{}, std::move(cell)};

  auto val = co_await RootContractConfig::load_from_state(cs, is_testnet());

  LOG_CHECK(val->is_test() == is_test()) << "test mode mismatch";

  if (runner_config_) {
    if (runner_config_->root_contract_config->version() < val->version()) {
      set_root_contract_config(std::move(val), ts);
    } else if (runner_config_->root_contract_config->version() == val->version()) {
      if (runner_config_->root_contract_ts < ts) {
        runner_config_->root_contract_ts = ts;
      }
    }
  } else {
    set_root_contract_config(std::move(val), ts);
  }
  co_return td::Unit();
}

/*
 *
 * HTTP
 *
 */
td::actor::Task<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
BaseRunner::generate_perf_stats(HttpUrlInfo info) {
  auto actor_stats = co_await td::actor::ask(actor_stats_, &td::actor::ActorStats::prepare_stats);
  co_return http_gen_static_answer(td::BufferSlice(actor_stats), "text/plain; charset=utf-8");
}

void BaseRunner::http_send_static_answer(
    td::Result<td::BufferSlice> R,
    td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise,
    std::string content_type) {
  promise.set_result(http_gen_static_answer(std::move(R), std::move(content_type)));
}

td::Result<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
BaseRunner::http_gen_static_answer(td::Result<td::BufferSlice> R, std::string content_type) {
  ton::http::HttpStatusCode status_code = ton::http::HttpStatusCode::status_ok;
  std::string status = "ok";
  td::BufferSlice data;

  if (R.is_error()) {
    auto code = R.error().code();
    switch (code) {
      case ton::ErrorCode::cancelled:
      case ton::ErrorCode::notready:
        status_code = ton::http::HttpStatusCode::status_bad_gateway;
        status = "bad gateway";
        break;
      case ton::ErrorCode::timeout:
        status_code = ton::http::HttpStatusCode::status_gateway_timeout;
        status = "gateway timeout";
        break;
      case ton::ErrorCode::error:
      case ton::ErrorCode::protoviolation:
      case ton::ErrorCode::warning:
        status_code = ton::http::HttpStatusCode::status_bad_request;
        status = "bad request";
        break;
      case ton::ErrorCode::failure:
      default:
        status_code = ton::http::HttpStatusCode::status_internal_server_error;
        status = "internal server error";
        break;
    }
    data = td::BufferSlice(td::Slice(PSTRING() << "received error: " << R.move_as_error() << "\n"));
  } else {
    data = R.move_as_ok();
  }

  auto response = ton::http::HttpResponse::create("HTTP/1.0", status_code, status, false, false).move_as_ok();

  response->add_header(ton::http::HttpHeader{"Access-Control-Allow-Origin", "*"});
  response->add_header(ton::http::HttpHeader{"Access-Control-Allow-Methods", "GET, POST, OPTIONS"});
  response->add_header(ton::http::HttpHeader{"Access-Control-Allow-Headers", "Content-Type, Authorization"});
  response->add_header(ton::http::HttpHeader{"Content-Type", content_type});
  response->add_header(ton::http::HttpHeader{"Content-Length", PSTRING() << data.size()});
  response->complete_parse_header();

  auto P = response->create_empty_payload().move_as_ok();
  P->add_chunk(std::move(data));
  P->complete_parse();
  return std::make_pair(std::move(response), std::move(P));
}

td::Result<BaseRunner::HttpUrlInfo> BaseRunner::http_parse_url(std::string url) {
  BaseRunner::HttpUrlInfo res;
  td::Slice S = url;
  auto p = S.find('?');
  if (p == td::Slice::npos) {
    res.url = url;
    return res;
  }
  res.url = url.substr(0, p);
  S.remove_prefix(p + 1);
  while (S.size() > 0) {
    auto x = S.find('&');
    td::Slice a;
    if (x == td::Slice::npos) {
      a = S;
      S = td::Slice();
    } else {
      a = S.copy().truncate(x);
      S.remove_prefix(x + 1);
    }

    x = a.find('=');
    if (x == td::Slice::npos) {
      res.get_args.emplace(a.str(), "");
    } else {
      res.get_args.emplace(a.copy().truncate(x).str(), a.copy().remove_prefix(x + 1).str());
    }
  }
  return res;
}

/*
 *
 * QUERIES AND MESSAGES 
 *
 */

void BaseRunner::send_query_to_proxy(std::string name, td::BufferSlice data, td::Timestamp timeout,
                                     td::Promise<td::BufferSlice> promise) {
  for (auto &x : proxy_targets_) {
    if (x.second->is_ready()) {
      send_query_to_connection(x.second->connection_id(), std::move(name), std::move(data), timeout,
                               std::move(promise));
      return;
    }
  }
  promise.set_error(td::Status::Error(ton::ErrorCode::notready, "No proxy connections"));
}

void BaseRunner::send_query_to_connection(TcpClient::ConnectionId connection_id, std::string name, td::BufferSlice data,
                                          td::Timestamp timeout, td::Promise<td::BufferSlice> promise) {
  auto it = all_connections_.find(connection_id);
  if (it == all_connections_.end()) {
    promise.set_error(td::Status::Error(ton::ErrorCode::notready, "connection is not ready"));
    return;
  }
  if (!it->second->is_ready()) {
    promise.set_error(td::Status::Error(ton::ErrorCode::notready, "connection is not ready"));
    return;
  }

  auto P = td::PromiseCreator::lambda(
      [connection_id, promise = std::move(promise), self = actor_id(this)](td::Result<td::BufferSlice> R) mutable {
        td::actor::send_closure(self, &BaseRunner::receive_answer_from_connection, connection_id, std::move(R),
                                std::move(promise));
      });

  td::actor::send_closure(client_.get(), &TcpClient::send_query, name, connection_id, std::move(data), timeout,
                          std::move(P));
  it->second->sent_query();
}

void BaseRunner::send_handshake_query_to_connection(TcpClient::ConnectionId connection_id, std::string name,
                                                    td::BufferSlice data, td::Timestamp timeout,
                                                    td::Promise<td::BufferSlice> promise) {
  auto it = all_connections_.find(connection_id);
  if (it == all_connections_.end()) {
    promise.set_error(td::Status::Error(ton::ErrorCode::notready, "connection is not ready"));
    return;
  }
  if (!it->second->is_connected()) {
    promise.set_error(td::Status::Error(ton::ErrorCode::notready, "connection is not ready"));
    return;
  }

  auto P = td::PromiseCreator::lambda(
      [connection_id, promise = std::move(promise), self = actor_id(this)](td::Result<td::BufferSlice> R) mutable {
        td::actor::send_closure(self, &BaseRunner::receive_answer_from_connection, connection_id, std::move(R),
                                std::move(promise));
      });

  td::actor::send_closure(client_.get(), &TcpClient::send_query, name, connection_id, std::move(data), timeout,
                          std::move(P));
  it->second->sent_query();
}

void BaseRunner::send_message_to_connection(TcpClient::ConnectionId connection_id, td::BufferSlice data) {
  auto it = all_connections_.find(connection_id);
  if (it == all_connections_.end()) {
    return;
  }
  if (!it->second->is_ready()) {
    return;
  }

  td::actor::send_closure(client_.get(), &TcpClient::send_packet, connection_id, std::move(data));
  it->second->sent_message();
}

void BaseRunner::receive_answer_from_connection(TcpClient::ConnectionId connection_id,
                                                td::Result<td::BufferSlice> result,
                                                td::Promise<td::BufferSlice> promise) {
  LOG(DEBUG) << "received answer from connection " << connection_id;
  auto it = all_connections_.find(connection_id);
  if (it == all_connections_.end()) {
    LOG(WARNING) << "received answer from unknown connection " << connection_id;
    return promise.set_error(td::Status::Error(ton::ErrorCode::cancelled, "connection is destroyed"));
  }
  it->second->received_answer();

  promise.set_result(std::move(result));
}

/*
 *
 * SC
 *
 */

block::StdAddress BaseRunner::generate_client_sc_address(td::Bits256 proxy_public_key,
                                                         const block::StdAddress &proxy_owner_address,
                                                         const block::StdAddress &proxy_sc_address,
                                                         const block::StdAddress &client_owner_address,
                                                         std::shared_ptr<RunnerConfig> config) {
  return ClientContract(client_owner_address, proxy_sc_address, proxy_public_key, this, config).address();
}

block::StdAddress BaseRunner::generate_worker_sc_address(td::Bits256 proxy_public_key,
                                                         const block::StdAddress &proxy_owner_address,
                                                         const block::StdAddress &proxy_sc_address,
                                                         const block::StdAddress &worker_owner_address,
                                                         std::shared_ptr<RunnerConfig> config) {
  return WorkerContract(worker_owner_address, proxy_sc_address, proxy_public_key, this, config).address();
}

block::StdAddress BaseRunner::generate_proxy_sc_address(td::Bits256 proxy_public_key,
                                                        const block::StdAddress &proxy_owner_address,
                                                        std::shared_ptr<RunnerConfig> config) {
  return ProxyContract(proxy_owner_address, proxy_public_key, nullptr, this, config).address();
}

td::Ref<vm::Cell> BaseRunner::generate_sc_init_data(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data) {
  vm::CellBuilder cb;
  cb.store_long(0, 2).store_long(3, 2).store_ref(code).store_ref(data).store_long(0, 1);

  return cb.finalize();
}

block::StdAddress BaseRunner::generate_sc_address(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, bool is_test,
                                                  bool is_bouncable) {
  auto c = generate_sc_init_data(code, data);
  return block::StdAddress{0, c->get_hash().as_bitslice().bits(), is_bouncable, is_test};
}

block::StdAddress BaseRunner::generate_sc_address(td::Ref<vm::Cell> init_data, bool is_test, bool is_bouncable) {
  return block::StdAddress{0, init_data->get_hash().as_bitslice().bits(), is_bouncable, is_test};
}

/*
 *
 * SC MESSAGES
 *
 */

td::Ref<vm::Cell> BaseRunner::sign_message(td::Ed25519::PrivateKey &pk, td::Ref<vm::Cell> msg) {
  auto hash = msg->get_hash();
  auto signature = pk.sign(hash.as_slice()).move_as_ok();
  CHECK(signature.size() == 64);

  vm::CellSlice cs{vm::NoVm{}, msg};

  vm::CellBuilder cb;
  cb.store_bytes(signature.as_slice());
  cb.store_bits(cs.as_bitslice());
  while (cs.have_refs()) {
    cb.store_ref(cs.fetch_ref());
  }

  return cb.finalize();
}

td::Ref<vm::Cell> BaseRunner::sign_and_wrap_message(td::Ed25519::PrivateKey &pk, td::Ref<vm::Cell> msg,
                                                    const block::StdAddress &return_excesses_to) {
  vm::CellSlice cs{vm::NoVm{}, msg};
  unsigned long long op, qid;
  CHECK(cs.fetch_ulong_bool(32, op));
  CHECK(cs.fetch_ulong_bool(64, qid));

  auto hash = msg->get_hash();
  auto signature = pk.sign(hash.as_slice()).move_as_ok();
  CHECK(signature.size() == 64);

  vm::CellBuilder cb;
  cb.store_long(op, 32).store_long(qid, 64);
  store_address(cb, return_excesses_to);
  cb.store_bytes(signature.as_slice()).store_ref(msg);

  return cb.finalize();
}

/*
 *
 * SC MONITOR 
 *
 */
void BaseRunner::add_smartcontract(std::shared_ptr<TonScWrapper> sc) {
  monitored_accounts_.emplace_back(sc);
  if (!monitored_accounts_update_running_) {
    run_monitor_accounts();
  }
}

void BaseRunner::del_smartcontract(TonScWrapper *sc) {
  for (auto &m : monitored_accounts_) {
    if (m.get() == sc) {
      std::swap(m, monitored_accounts_.back());
      monitored_accounts_.pop_back();
      return;
    }
  }
  UNREACHABLE();
}

bool BaseRunner::sc_is_alive(td::int64 id) {
  for (auto &sc : monitored_accounts_) {
    if (sc->id() == id) {
      return true;
    }
  }
  return false;
}

void BaseRunner::run_monitor_accounts() {
  if (ton_disabled()) {
    return;
  }
  CHECK(!monitored_accounts_update_running_);
  monitored_accounts_update_running_ = true;
  td::MultiPromise p;
  auto ig = p.init_guard();
  ig.add_promise([self_id = actor_id(this)](td::Result<td::Unit> R) {
    td::actor::send_closure(self_id, &BaseRunner::monitored_accounts_update_completed);
  });

  for (auto &t : monitored_accounts_) {
    t->request_updates(ig.get_promise());
  }
}

void BaseRunner::monitored_accounts_update_completed() {
  monitored_accounts_update_running_ = false;
}

/*
 *
 * COCOON WALLET
 *
 */

void BaseRunner::cocoon_wallet_initialize_wait_for_balance_and_get_seqno(td::SecureString wallet_private_key,
                                                                         block::StdAddress wallet_owner,
                                                                         td::uint64 min_balance,
                                                                         td::Promise<td::Unit> promise) {
  cocoon_wallet_ =
      std::make_shared<CocoonWallet>(std::move(wallet_private_key), wallet_owner, min_balance, this, runner_config_);
  cocoon_wallet_->subscribe_to_updates(cocoon_wallet_);
  cocoon_wallet_check_balance(std::move(promise));
}

void BaseRunner::cocoon_wallet_check_balance(td::Promise<td::Unit> promise) {
  delay_action(td::Timestamp::in(td::Random::fast(1.0, 2.0)), [this, promise = std::move(promise)]() mutable {
    if (ton_disabled()) {
      cocoon_wallet_->deploy(std::move(promise));
      return;
    }
    if (!cocoon_wallet_->is_started()) {
      cocoon_wallet_check_balance(std::move(promise));
    } else if (cocoon_wallet_->balance() >= cocoon_wallet_->min_balance()) {
      promise.set_value(td::Unit());
    } else {
      LOG(ERROR) << "ACTION REQUIRED: BALANCE ON CONTRACT " << cocoon_wallet_->address().rserialize(true)
                 << " IS TOO LOW: MINIMUM " << cocoon_wallet_->min_balance() << " CURRENT "
                 << cocoon_wallet_->balance();
      cocoon_wallet_check_balance(std::move(promise));
    }
  });
}

/* 
 *
 * STAT 
 *
 */

void BaseRunner::store_wallet_stat(td::StringBuilder &sb) {
  auto w = cocoon_wallet_;
  if (!w) {
    return;
  }
  sb << "<h1>WALLET</h1>\n";
  sb << "<table>\n";
  sb << "<tr><td>address</td><td>" << address_link(w->address()) << "</td></tr>\n";
  sb << "<tr><td>balance</td><td>" << to_ton(w->balance()) << "</td></tr>\n";
  sb << "<tr><td>seqno</td><td>" << w->seqno() << "</td></tr>\n";
  sb << "<tr><td>pending transactions</td><td>" << w->pending_transactions_cnt() << "</td></tr>\n";
  sb << "<tr><td>active transactions</td><td>" << w->active_transactions_cnt() << "</td></tr>\n";
  sb << "</table>\n";
}
void BaseRunner::store_wallet_stat(SimpleJsonSerializer &jb) {
  auto w = cocoon_wallet_;
  if (!w) {
    return;
  }
  jb.start_object("wallet");
  jb.add_element("address", w->address().rserialize(true));
  jb.add_element("balance", w->balance());
  jb.add_element("seqno", w->seqno());
  jb.add_element("pending_transactions_cnt", w->pending_transactions_cnt());
  jb.add_element("active_transactions_cnt", w->active_transactions_cnt());
  jb.stop_object();
}
void BaseRunner::store_root_contract_stat(td::StringBuilder &sb) {
  auto conf = runner_config();
  if (conf) {
    sb << "<h1>GLOBAL CONFIG</h1>\n";
    conf->root_contract_config->store_stat(this, sb);
  }
}
void BaseRunner::store_root_contract_stat(SimpleJsonSerializer &jb) {
  auto conf = runner_config();
  if (conf) {
    conf->root_contract_config->store_stat(this, jb);
  }
}

}  // namespace cocoon
