// anynet
// Copyright (C) 2009  Steven Siloti
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects
// for all of the code used other than OpenSSL.  If you modify
// file(s) with this exception, you may extend this exception to your
// version of the file(s), but you are not obligated to do so.  If you
// do not wish to do so, delete this exception statement from your
// version.  If you delete this exception statement from all source
// files in the program, then also delete it here.
//
// Contact:  Steven Siloti <ssiloti@gmail.com>

#include "trivial_transport.hpp"
#include "node.hpp"
#include <boost/make_shared.hpp>
#include <boost/cstdint.hpp>

using namespace transport;

namespace
{
	struct connection_ep_comparator
	{
		connection_ep_comparator(ip::tcp::endpoint ep) : ep_(ep) {}

		bool operator()(boost::shared_ptr<trivial::connection> c)
		{
			return c->remote_endpoint() == ep_;
		}

		ip::tcp::endpoint ep_;
	};

	template <typename Adr>
	struct link_handshake
	{
		uint8_t sig[10];
		uint8_t version;
		uint8_t rsvd;
		typename Adr::bytes_type remote_ip;
		uint8_t incoming_port[2];
	};

	const char* handshake_signature = "AN_TRIVIAL";

	struct packed_message
	{
		uint8_t protocol[2];
		uint8_t status;
		uint8_t reserved[5];
		uint8_t content_size[8];
	};

	struct packed_content_id
	{
		uint8_t publisher[network_key::packed_size];
		uint8_t name[];
	};
}

trivial::connection::connection(boost::shared_ptr<trivial> m)
	: manager_(m)
	, link_(m->node_->io_service(), m->node_->context)
	, tx_ready_(false)
{}

void trivial::connection::send(const message& msg)
{
	send_queue_.push_back(msg);
	if (tx_ready_ && send_queue_.size() == 1)
		send_next_message();
}

void trivial::connection::message_sent(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	send_queue_.pop_front();

	if (!send_queue_.empty())
		send_next_message();
}

void trivial::connection::send_next_message()
{
	link_.clear_send_buffer();

	packed_message* msg = buffer_cast<packed_message*>(link_.send_buffer(sizeof(packed_message)));
	u16(msg->protocol, send_queue_.front().pid);
	msg->status = send_queue_.front().status;
	std::memset(msg->reserved, 0, sizeof(msg->reserved));

	std::vector<const_buffer> send_buffers;

	std::size_t payload_size;

	switch (msg->status)
	{
	case message::status_requested:
	case message::status_failed:
		{
			payload_size = sizeof(packed_content_id) + send_queue_.front().cid.name.serialize(mutable_buffer());
			packed_content_id* cid = buffer_cast<packed_content_id*>(link_.send_buffer(payload_size));
			send_queue_.front().cid.publisher.encode(cid->publisher);
			send_queue_.front().cid.name.serialize(cid->name);
			break;
		}
	case message::status_attached:
		payload_size = buffer_size(send_queue_.front().payload->get());
		send_buffers.push_back(send_queue_.front().payload->get());
		break;
	}

	u64(msg->content_size, payload_size);

	send_buffers.insert(send_buffers.begin(), link_.sendable_buffer());

	boost::asio::async_write(link_.socket,
	                         send_buffers,
	                         boost::bind(&connection::message_sent,
	                                     shared_from_this(),
	                                     placeholders::error,
	                                     placeholders::bytes_transferred));
}

void trivial::connection::receive_next_message()
{
	link_.make_valid(sizeof(packed_message),
	                 boost::bind(&connection::message_header_received,
	                             shared_from_this(),
	                             placeholders::error,
	                             placeholders::bytes_transferred));
}

void trivial::connection::message_header_received(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	link_.received(bytes_transferred);

	const packed_message* m = buffer_cast<const packed_message*>(link_.received_buffer());

	if (m->status == 2 || u64(m->content_size) > std::numeric_limits<std::size_t>::max()) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	message msg;
	std::size_t payload_size(std::size_t(u64(m->content_size)));

	msg.pid = u16(m->protocol);
	msg.status = message::payload_status(m->status & 0x03);

	link_.consume_receive_buffer(sizeof(packed_message));

	if (!manager_->valid_protocol(msg.pid)) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	switch (msg.status)
	{
	case message::status_requested:
	case message::status_failed:
		link_.make_valid(payload_size,
		                 boost::bind(&connection::message_payload_received,
		                             shared_from_this(),
		                             msg,
		                             placeholders::error,
		                             placeholders::bytes_transferred));
		break;
	case message::status_attached:
		{
			payload_buffer_ptr payload = manager_->get_payload_buffer(msg.pid, payload_size);
			msg.payload = payload;
			link_.receive_into(std::vector<mutable_buffer>(1, payload.get()->get()),
			                   boost::bind(&connection::message_payload_received,
			                               shared_from_this(),
			                               msg,
			                               placeholders::error,
			                               placeholders::bytes_transferred));
			break;
		}
	}
}

void trivial::connection::message_payload_received(message msg,
                                                   const boost::system::error_code& error,
                                                   std::size_t bytes_transferred)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	switch (msg.status)
	{
	case message::status_requested:
	case message::status_failed:
		{
			link_.received(bytes_transferred);
			const packed_content_id* cid = buffer_cast<const packed_content_id*>(link_.received_buffer());
			msg.cid.publisher.decode(cid->publisher);
			link_.consume_receive_buffer(sizeof(packed_content_id) + msg.cid.name.parse(cid->name));
			break;
		}
	case message::status_attached:
		try {
			msg.cid = manager_->upper_layers_[msg.pid]->content_id(msg.payload->get());
		} catch (bad_content e) {
			manager_->connection_failure(shared_from_this());
			return;
		}
		break;
	}

	manager_->message_received(shared_from_this(), msg);
	receive_next_message();
}

void trivial::connection::connect(ip::tcp::endpoint ep)
{
	assert(ep.port() >= 11100);
	link_.socket.lowest_layer().async_connect(ep, boost::bind(&connection::ssl_handshake,
	                                                          shared_from_this(),
	                                                          boost::asio::ssl::stream_base::client,
	                                                          placeholders::error));
}

void trivial::connection::accept(ip::tcp::acceptor& incoming)
{
	incoming.async_accept(link_.socket.lowest_layer(),
	                      boost::bind(&connection::connection_accepted,
	                                  shared_from_this(),
	                                  placeholders::error));
}

void trivial::connection::stop()
{
	link_.socket.lowest_layer().close();
	manager_->connection_finished(shared_from_this());
}

const_buffer trivial::connection::generate_handshake()
{
	if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
		return do_generate_handshake<ip::address_v4>();
	else
		return do_generate_handshake<ip::address_v6>();
}

template <typename Adr>
const_buffer trivial::connection::do_generate_handshake()
{
	link_handshake<Adr>* handshake = buffer_cast<link_handshake<Adr>*>( link_.send_buffer(sizeof(link_handshake<Adr>)));

	std::memcpy(handshake->sig, handshake_signature, sizeof(handshake->sig));
	handshake->version = version;
	handshake->remote_ip = to<Adr>(link_.socket.lowest_layer().remote_endpoint().address()).to_bytes();
	u16(handshake->incoming_port, manager_->acceptor_.local_endpoint().port());
	handshake->rsvd = 0;

	return link_.sendable_buffer();
}

template <typename Adr>
bool trivial::connection::parse_handshake()
{
//	DLOG(INFO) << "Parsing handshake";
	const link_handshake<Adr>* handshake = buffer_cast<const link_handshake<Adr>*>(link_.received_buffer());

	if (std::memcmp(handshake->sig, handshake_signature, sizeof(handshake->sig)) || handshake->version != version)
		return false;

	remote_public_endpoint_ = link_.socket.lowest_layer().remote_endpoint();
	remote_public_endpoint_.port(u16(handshake->incoming_port));

	link_.consume_receive_buffer(sizeof(link_handshake<Adr>));

	return true;
}

void trivial::connection::connection_accepted(const boost::system::error_code& error)
{
	manager_->connection_accepted(shared_from_this(), error);

	if (!error)
		ssl_handshake(boost::asio::ssl::stream_base::server, error);
}

void trivial::connection::ssl_handshake(boost::asio::ssl::stream_base::handshake_type type, const boost::system::error_code& error)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	link_.socket.async_handshake(type,
	                             boost::bind(&connection::write_handshake,
	                                         shared_from_this(),
	                                         boost::asio::placeholders::error));
}

void trivial::connection::write_handshake(const boost::system::error_code& error)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	boost::asio::async_write(link_.socket,
	                         const_buffers_1(generate_handshake()),
	                         boost::bind(&connection::read_handshake,
	                                     shared_from_this(),
	                                     placeholders::error,
	                                     placeholders::bytes_transferred));
}

void trivial::connection::read_handshake(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	boost::asio::async_read(link_.socket,
	                        mutable_buffers_1(link_.receive_buffer()),
	                        boost::asio::transfer_at_least(bytes_transferred),
	                        boost::bind(&connection::handshake_received,
	                                    shared_from_this(),
	                                    placeholders::error,
	                                    placeholders::bytes_transferred));
}

void trivial::connection::handshake_received(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error) {
		manager_->connection_failure(shared_from_this());
		return;
	}

	link_.received(bytes_transferred);

	bool handshake_valid;

	if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
		handshake_valid = parse_handshake<ip::address_v4>();
	else
		handshake_valid = parse_handshake<ip::address_v6>();

	if (!handshake_valid) {
		manager_->connection_failure(shared_from_this());
		DLOG(INFO) << "Error parsing handshake";
		return;
	}

	remote_identity_ = network_key(::SSL_get_peer_certificate(link_.socket.impl()->ssl));
	tx_ready_ = true;
	if (!send_queue_.empty())
		send_next_message();
	receive_next_message();
}

trivial::request::request(boost::asio::io_service& ios, boost::shared_ptr<content_sources> sources)
	: sources_(sources), timeout_(ios), running_(false)
{
}

bool trivial::request::failure(boost::shared_ptr<trivial> manager,
                               const network_key& src,
                               protocol_id pid,
                               const content_identifier& cid)
{
	if (!running_)
		return false;

	if (src == outstanding_request_)
		sources_->sources.erase(src);
	if (!sources_->sources.empty())
		start(manager, pid, cid);
	else
		running_ = false;

	return running_;
}

void trivial::request::start(boost::shared_ptr<trivial> manager, protocol_id pid, const content_identifier& cid)
{
	running_ = true;

	message msg;
	msg.pid = pid;
	msg.cid = cid;
	msg.status = message::status_requested;

	// TODO: pick best peer based on credits and id distance, for now just pull from the head
	manager->send(sources_->sources.begin()->second.ep, msg);
	outstanding_request_ = sources_->sources.begin()->first;

	timeout_.expires_from_now(boost::posix_time::seconds(60));
	timeout_.async_wait(boost::bind(&trivial::request_timeout,
	                                manager,
	                                sources_->sources.begin()->first,
	                                pid,
	                                cid,
	                                placeholders::error));
}

void trivial::request::stop()
{
	running_ = false;
	timeout_.cancel();
}

trivial::trivial(boost::shared_ptr<local_node> node)
	: network_transport(0, node)
	, acceptor_(node->io_service())
	, running_(false)
{
	ip::tcp::endpoint listen_ep(ip::address::from_string(node_->config().listen_ip()), node_->config().listen_port() + 100);

	acceptor_.open(listen_ep.protocol());
	acceptor_.set_option(ip::tcp::socket::reuse_address(true));
	for (;listen_ep.port() < node_->config().listen_port() + 200; listen_ep.port( listen_ep.port() + 1 )) {
		boost::system::error_code error;
		acceptor_.bind(listen_ep, error);
		if (!error) break;
	}
	acceptor_.listen();
}

void trivial::start()
{
	if (!running_) {
		running_ = true;
		boost::make_shared<connection>(shared_from_this())->accept(acceptor_);
	}
}

void trivial::stop()
{
	running_ = false;
	acceptor_.close();
	std::for_each(connections_.begin(), connections_.end(), boost::bind(&connection::stop, _1));
	connections_.clear();
}

ip::tcp::endpoint trivial::public_endpoint() const
{
	ip::tcp::endpoint ep(node_->public_endpoint());
	ep.port(acceptor_.local_endpoint().port());
	return ep;
}

bool trivial::is_connected(ip::tcp::endpoint ep)
{
	return std::find_if(connections_.begin(), connections_.end(), connection_ep_comparator(ep)) != connections_.end();
}

void trivial::start_request(protocol_id pid, const content_identifier& cid, boost::shared_ptr<content_sources> sources)
{
	if (!running_)
		return;

	auto req = requests_.insert(std::make_pair(std::make_pair(pid, cid), boost::shared_ptr<request>()));

	if (req.second) {
		req.first->second = boost::make_shared<request>(boost::ref(node_->io_service()), sources);
		req.first->second->start(shared_from_this(), pid, cid);
	}
}

void trivial::stop_request(protocol_id pid, const content_identifier& cid)
{
	auto req = requests_.find(std::make_pair(pid, cid));

	if (req != requests_.end()) {
		req->second->stop();
		requests_.erase(req);
	}
}

void trivial::send(ip::tcp::endpoint ep, const message& msg)
{
	if (running_) {
		auto con = std::find_if(connections_.begin(), connections_.end(), connection_ep_comparator(ep));

		if (con == connections_.end())
		{
			connections_.push_back(boost::make_shared<trivial::connection>(shared_from_this()));
			con = --connections_.end();
			con->get()->connect(ep);
		}

		con->get()->send(msg);
	}
}

void trivial::register_upper_layer(protocol_id pid, boost::shared_ptr<upper_layer> upper)
{
	bool inserted = upper_layers_.insert(std::make_pair(pid, upper)).second;
	assert(inserted);
}

void trivial::connection_accepted(boost::shared_ptr<connection> con, const boost::system::error_code& error)
{
	if (!error) {
		assert(!is_connected(con->link_.socket.lowest_layer().remote_endpoint()));
		connections_.push_back(con);
		if (running_)
			boost::make_shared<connection>(shared_from_this())->accept(acceptor_);
	}
}

void trivial::connection_failure(boost::shared_ptr<connection> con)
{
	auto con_itr = std::find(connections_.begin(), connections_.end(), con);

	if (con_itr != connections_.end())
		connections_.erase(con_itr);

	con->stop();
}

void trivial::connection_finished(boost::shared_ptr<connection> con)
{
	for (std::deque<message>::iterator msg = con->send_queue_.begin(); msg != con->send_queue_.end(); ++msg)
		if (msg->status == message::status_requested)
			upper_layers_[msg->pid]->content_finished(msg->cid, const_payload_buffer_ptr());
	con->send_queue_.clear();
}

bool trivial::valid_protocol(protocol_id pid)
{
	return upper_layers_.count(pid) != 0;
}

payload_buffer_ptr trivial::get_payload_buffer(protocol_id pid, std::size_t size)
{
	return upper_layers_[pid]->get_payload_buffer(size);
}

void trivial::message_received(boost::shared_ptr<connection> con, message& msg)
{
	switch (msg.status)
	{
	case message::status_attached:
	case message::status_failed:
		{
			auto req = requests_.find(std::make_pair(msg.pid, msg.cid));

			if (msg.status == message::status_attached) {
				req->second->stop();
				requests_.erase(req);
				upper_layers_[msg.pid]->content_finished(msg.cid, msg.payload);
			}
			else if (msg.status == message::status_failed && !req->second->failure(shared_from_this(), con->remote_id(), msg.pid, msg.cid)) {
				upper_layers_[msg.pid]->content_finished(msg.cid, const_payload_buffer_ptr());
				requests_.erase(req);
			}
			break;
		}
	case message::status_requested:
		msg.payload = upper_layers_[msg.pid]->get_content(msg.cid);
		if (msg.payload)
			msg.status = message::status_attached;
		else
			msg.status = message::status_failed;
		con->send(msg);
		break;
	}
}

void trivial::request_timeout(const network_key& src,
                              protocol_id pid,
                              const content_identifier& cid,
                              const boost::system::error_code& error)
{
	if (error || !running_)
		return;

	auto req = requests_.find(std::make_pair(pid, cid));

	if (req != requests_.end() && !req->second->failure(shared_from_this(), src, pid, cid)) {
		upper_layers_[pid]->content_finished(cid, const_payload_buffer_ptr());
		requests_.erase(req);
	}
}
