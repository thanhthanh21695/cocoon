#include "cocoon/FwdProxy.h"
#include "cocoon/pow.h"
#include "td/net/SslStream.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/optional.h"
#include "td/utils/format.h"
#include "tdx.h"
#include "utils.h"
#include "td/net/Pipe.h"
#include "td/net/utils.h"

#include <optional>

namespace cocoon {
struct Answer {
  td::SocketPipe src;
  td::SocketPipe dst;
  tdx::PolicyRef policy;
  td::IPAddress destination;
};

class Socks5Init : public td::TaskActor<Answer> {
 public:
  Socks5Init(td::SocketPipe pipe, std::shared_ptr<const FwdProxy::Config> config)
      : pipe_(std::move(pipe)), config_(std::move(config)) {
  }

 private:
  void start_up() override {
    pipe_.subscribe();
  }
  static constexpr int WaitCode = 123;

  td::Result<std::string> read(td::ChainBufferReader &reader, size_t size) {
    if (size > reader.size()) {
      return td::Status::Error<WaitCode>();
    }
    std::string res(size, '\0');
    reader.advance(size, res);
    return res;
  }

  td::Status wait_greeting() {
    auto buf = pipe_.input_buffer().clone();
    TRY_RESULT(header, read(buf, 2));
    td::uint8 version = header[0];
    if (version != 0x5) {
      return td::Status::Error(PSLICE() << "Expected 0x5 version, got " << version);
    }
    td::uint8 methods_n = header[1];
    TRY_RESULT(methods, read(buf, methods_n));

    pipe_.input_buffer() = std::move(buf);

    bool user_password_found = false;
    bool no_auth_found = false;
    for (auto &method : methods) {
      LOG(INFO) << "method:" << int(method);
      if (method == 2 && config_->allow_policy_from_username_) {  // "user/password"
        user_password_found = true;
      } else if (method == 0) {  // no user password
        no_auth_found = true;
      }
    }
    if (!user_password_found && !no_auth_found) {
      return td::Status::Error("Only user/password or no auth are supported");
    }

    if (!user_password_found) {
      LOG(INFO) << "use default policy";
      TRY_STATUS(set_policy_name(config_->default_policy_));
    }

    unsigned char ans[2];
    ans[0] = 0x5;                              // version
    ans[1] = user_password_found ? 0x2 : 0x0;  // user/password

    pipe_.output_buffer().append(td::Slice(ans, 2));
    if (user_password_found) {
      state_ = State::WaitAuth;
    } else {
      state_ = State::WaitRequest;
    }

    return td::Status::OK();
  }

  td::Status wait_auth() {
    auto buf = pipe_.input_buffer().clone();
    TRY_RESULT(header, read(buf, 2));
    td::uint8 version = header[0];
    if (version != 0x1) {
      return td::Status::Error(PSLICE() << "Invalid socks5 auth version " << version << ", expected 0x1");
    }
    td::uint8 user_length = header[1];
    TRY_RESULT(user, read(buf, user_length));

    TRY_RESULT(header2, read(buf, 1));
    td::uint8 password_length = header2[0];
    TRY_RESULT(password, read(buf, password_length));

    TRY_STATUS(set_policy_name(user));

    pipe_.input_buffer() = std::move(buf);

    unsigned char ans[2];
    ans[0] = 0x1;  // version
    ans[1] = 0x0;  // status
    pipe_.output_buffer().append(td::Slice(ans, 2));
    state_ = State::WaitRequest;
    return td::Status::OK();
  }

  td::Status set_policy_name(const std::string &policy_name) {
    LOG(ERROR) << "set policy name = " << policy_name;
    TRY_RESULT_ASSIGN(policy_, config_->find_policy(policy_name));
    return td::Status::OK();
  }

  td::Status wait_request() {
    auto buf = pipe_.input_buffer().clone();
    TRY_RESULT(header, read(buf, 4));
    td::uint8 version = header[0];
    td::uint8 cmd = header[1];
    td::uint8 address_type = header[3];
    if (version != 0x5) {
      return td::Status::Error(PSLICE() << "Invalid socks5 request version " << version << ", expected 0x5");
    }
    if (cmd != 0x1) {
      return td::Status::Error(PSLICE() << "Unsupported socks5 command " << cmd);
    }
    std::string host;
    if (address_type == 1) {  // ipv4
      TRY_RESULT(ipv4, read(buf, 4));
      host = PSTRING() << int(td::uint8(ipv4[0])) << "." << int(td::uint8(ipv4[1])) << "." << int(td::uint8(ipv4[2]))
                       << "." << int(td::uint8(ipv4[3]));
    } else if (address_type == 3) {  // host
      return td::Status::Error("TODO: support host destination in socks5");
    } else if (address_type == 4) {  // ipv6
      return td::Status::Error("TODO: support ipv6 destination in socks5");
    } else {
      return td::Status::Error(PSLICE() << "Unsupported address type=" << address_type);
    }
    TRY_RESULT(port_raw, read(buf, 2));
    pipe_.input_buffer() = std::move(buf);

    td::int32 port = td::uint8(port_raw[0]) * 256 + td::uint8(port_raw[1]);
    TRY_STATUS(destination_.init_host_port(host, port));
    LOG(INFO) << "Connect " << destination_;
    TRY_RESULT(socket, td::SocketFd::open(destination_));
    td::IPAddress bound_address;
    TRY_STATUS(bound_address.init_socket_address(socket));
    auto bound_port = bound_address.get_port();

    td::string response;
    response += '\x05';
    response += '\x00';
    response += '\x00';
    if (bound_address.is_ipv4()) {
      response += '\x01';
      auto ipv4 = ntohl(bound_address.get_ipv4());
      response += static_cast<char>(ipv4 & 255);
      response += static_cast<char>((ipv4 >> 8) & 255);
      response += static_cast<char>((ipv4 >> 16) & 255);
      response += static_cast<char>((ipv4 >> 24) & 255);
    } else {
      response += '\x04';
      response += bound_address.get_ipv6();
    }
    response += static_cast<char>((bound_port >> 8) & 255);
    response += static_cast<char>(bound_port & 255);

    pipe_.output_buffer().append(response);
    dest_pipe_ = make_socket_pipe(std::move(socket));
    state_ = State::Done;
    return td::Status::OK();
  }

  td::Status run() {
    while (state_ != State::Done) {
      switch (state_) {
        case State::WaitGreeting:
          TRY_STATUS(wait_greeting());
          break;
        case State::WaitAuth:
          TRY_STATUS(wait_auth());
          break;
        case State::WaitRequest:
          TRY_STATUS(wait_request());
          break;
        case State::Done:
          break;
      }
    }
    return td::Status::OK();
  }

  td::Status do_loop() {
    TRY_STATUS(td::loop_read("left", pipe_));
    auto status = run();
    if (status.code() != WaitCode) {
      return status;
    }
    TRY_STATUS(td::loop_write("left", pipe_));
    return td::Status::OK();
  }

  td::actor::Task<Action> task_loop_once() override {
    co_await do_loop();
    co_return state_ == State::Done ? Action::Finish : Action::KeepRunning;
  }

  td::actor::Task<Answer> finish(td::Status status) override {
    LOG(INFO) << "Finish: status=" << status;
    co_await std::move(status);
    auto pipe_socket = co_await std::move(pipe_).extract_fd();
    co_return Answer{
        .src = td::make_socket_pipe(std::move(pipe_socket)),
        .dst = std::move(dest_pipe_),
        .policy = std::move(policy_),
        .destination = destination_,
    };
  }

  enum class State { WaitGreeting, WaitAuth, WaitRequest, Done } state_ = State::WaitGreeting;

  td::SocketPipe pipe_;
  td::SocketPipe dest_pipe_;
  tdx::PolicyRef policy_;
  td::IPAddress destination_;

  std::shared_ptr<const FwdProxy::Config> config_;
};

namespace {
struct AcceptAndProxy : td::TaskActor<ProxyState> {
  AcceptAndProxy(td::SocketFd socket, std::shared_ptr<const FwdProxy::Config> config) : socket_(std::move(socket)), config_(std::move(config)) {
  }
  td::actor::Task<Action> task_loop_once() override {
    state_.init_source(socket_);
    state_.update_state("Connecting");

    td::SocketPipe left;
    td::SocketPipe right;
    tdx::PolicyRef policy;

    if (config_->skip_socks5) {
      // Forward proxy mode: directly connect to fixed destination
      state_.destination_ = config_->fixed_destination_;
      left = make_socket_pipe(std::move(socket_));
      auto dest_socket = co_await td::SocketFd::open(config_->fixed_destination_);
      right = make_socket_pipe(std::move(dest_socket));
      policy = co_await config_->find_policy(config_->default_policy_);
    } else {
      // SOCKS5 mode: negotiate destination via SOCKS5
      state_.update_state("Socks5");
      auto ans = co_await td::spawn_task_actor<Socks5Init>("Socks5Init", make_socket_pipe(std::move(socket_)), config_);
      left = std::move(ans.src);
      right = std::move(ans.dst);
      policy = std::move(ans.policy);
      state_.destination_ = ans.destination;

    }

    auto desc = state_.short_desc();

    // Solve PoW challenge from remote RevProxy (client always checks for magic)
    state_.update_state("Pow");
    right = co_await pow::solve_pow_client(std::move(right), config_->max_pow_difficulty);

    state_.update_state("TlsHandshake");
    auto [tls_pipe, info] = co_await wrap_tls_client("-Fwd-" + desc, std::move(right), config_->cert_and_key_.load(), policy);
    state_.set_attestation(info);

    if (config_->serialize_info) {
      co_await framed_tl_write(left.output_buffer(), info);
    }

    state_.update_state("Proxying");
    co_await proxy("-Fwd-" + desc, std::move(left), std::move(tls_pipe));
    co_return Action::Finish;  // will move straight to finish
  }
  td::actor::Task<ProxyState> finish(td::Status status) override {
    state_.finish(std::move(status));
    co_return std::move(state_);
  }
private:
  td::SocketFd socket_;
  std::shared_ptr<const FwdProxy::Config> config_;
  ProxyState state_;
};
}  // namespace

td::Result<tdx::PolicyRef> FwdProxy::Config::find_policy(td::Slice username) const {
  auto it = policies_.find(username);
  if (it == policies_.end()) {
    return td::Status::Error(PSLICE() << "Unknown policy: " << username);
  }
  auto policy = it->second;
  CHECK(policy);
  return policy;
}
void FwdProxy::start_up() {
  struct Callback : public td::TcpListener::Callback {
    std::shared_ptr<const Config> config_;
    explicit Callback(std::shared_ptr<const Config> config) : config_(std::move(config)) {
    }
    void accept(td::SocketFd fd) override {
      td::actor::spawn_task_actor<AcceptAndProxy>("Fwd", std::move(fd), config_).detach_silent();
    }
  };
  listener_ = td::actor::create_actor<td::TcpInfiniteListener>("Listener", config_->port_,
                                                               std::make_unique<Callback>(config_), "127.0.0.1");
}
}  // namespace cocoon