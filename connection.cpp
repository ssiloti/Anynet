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

#include "connection.hpp"
#include "node.hpp"
#include "config.hpp"
#include <boost/asio/read.hpp>
#include <boost/bind/protect.hpp>
#include <algorithm>
#include <cstring>

#ifdef SIMULATION
#include "simulator.hpp"
#endif

const boost::posix_time::time_duration connection::target_latency(boost::posix_time::milliseconds(100));

template <typename Adr>
struct link_handshake
{
	boost::uint8_t sig[2];
	boost::uint8_t protocol;
	boost::uint8_t type;
	boost::uint8_t remote_ip[Adr::bytes_type::static_size];
	boost::uint8_t rsvd[2];
	boost::uint8_t incoming_port[2];
	boost::uint8_t remote_id[network_key::packed_size];
};

struct oob_threshold_frame
{
	boost::uint8_t type;
	boost::uint8_t rsvd[3];
	boost::uint8_t oob_threshold[4];
};

template <typename Adr>
struct successor_frame
{
	boost::uint8_t type;
	boost::uint8_t rsvd;
	boost::uint8_t sucessor_port[2];
	boost::uint8_t sucessor_ip[Adr::bytes_type::static_size];
};

connection::connection(local_node& node, routing_type rtype)
: node_(node), link_(node.io_service()), routing_type_(rtype), incoming_port_(0),
	lifecycle_(connecting), oob_threshold_(min_oob_threshold), local_oob_threshold_(min_oob_threshold), transfer_outstanding_(false),
	outstanding_non_packet_frames_(0)
{

}

ip::tcp::endpoint connection::remote_endpoint() const
{
	boost::system::error_code error;
	return ip::tcp::endpoint(link_.socket.remote_endpoint(error).address(), incoming_port_);
}

void connection::starting_connection()
{
	node_.connection_in_progress(shared_from_this());
}

void connection::stillborn()
{
	DLOG(INFO) << "Error while establishing connection";
	if (lifecycle_ != cleanup) {
		lifecycle_ = cleanup;
		node_.register_connection(shared_from_this());
	}
}

connection::ptr_t connection::connect(local_node& node, ip::tcp::endpoint peer, routing_type rtype)
{
	DLOG(INFO) << "Connecting: " << node.public_endpoint().port() << ", " << peer.address() << ':' << peer.port();
	ptr_t con(new connection(node, rtype));
	con->starting_connection();
	con->incoming_port_ = peer.port();
	con->link_.socket.async_connect( peer, boost::bind(&connection::write_handshake, con, placeholders::error) );
	return con;
}

void connection::connection_accepted(const boost::system::error_code& error, ip::tcp::acceptor& incoming)
{
	if (!error && lifecycle_ == connecting) {
		ptr_t con(new connection(node_, ib));
		con->starting_connection();
		incoming.async_accept( con->link_.socket, boost::bind(&connection::connection_accepted,
															  con,
															  placeholders::error,
															  boost::ref(incoming)) );
		
		write_handshake(boost::system::error_code());
	}
	else {
		if (lifecycle_ != cleanup) {
			disconnect();
			stillborn();
		}
	}
}

void connection::write_handshake(const boost::system::error_code& error)
{
	if (!error && lifecycle_ == connecting) {
		boost::asio::async_write(link_.socket,
		                         const_buffers_1(generate_handshake()),
		                         boost::bind(&connection::read_handshake,
		                                     shared_from_this(),
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
	}
	else {
		if (lifecycle_ != cleanup) {
			disconnect();
			stillborn();
		}
	}
}

void connection::read_handshake(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (!error && lifecycle_ == connecting) {
		boost::asio::async_read(link_.socket,
		                        mutable_buffers_1(link_.receive_buffer.data(), bytes_transferred),
		                        boost::bind(&connection::complete_connection,
		                                    shared_from_this(),
		                                    placeholders::error,
		                                    placeholders::bytes_transferred));
	}
	else {
		if (lifecycle_ != cleanup) {
			disconnect();
			stillborn();
		}
	}
}

template <typename Adr>
const_buffer connection::do_generate_handshake()
{
	link_handshake<Adr>* handshake = reinterpret_cast<link_handshake<Adr>*>(link_.send_buffer.data());
	handshake->sig[0] = 'A';
	handshake->sig[1] = 'N';
	handshake->protocol = link_.protocol_version;
	handshake->type = routing_type_;

	typename Adr::bytes_type peer_ip = to<Adr>(link_.socket.remote_endpoint().address()).to_bytes();
	std::memcpy(handshake->remote_ip, peer_ip.data(), peer_ip.size());

	u16(handshake->incoming_port, node_.config().listen_port());

	return const_buffer(link_.send_buffer.data(), sizeof(link_handshake<Adr>));
}

const_buffer connection::generate_handshake()
{
//	DLOG(INFO) << "Generating handshake";

	if (link_.socket.remote_endpoint().address().is_v4())
		return do_generate_handshake<ip::address_v4>();
	else
		return do_generate_handshake<ip::address_v6>();
}

template <typename Adr>
bool connection::do_parse_handshake()
{
//	DLOG(INFO) << "Parsing handshake";
	link_handshake<Adr>* handshake = reinterpret_cast<link_handshake<Adr>*>(link_.receive_buffer.data());

	if (handshake->sig[0] != 'A' || handshake->sig[1] != 'N' || handshake->protocol != link_.protocol_version)
		return false;

	routing_type_ = std::min(routing_type_, connection::routing_type(handshake->type & 0x03));
	incoming_port_ = u16(handshake->incoming_port);

	typename Adr::bytes_type ip_bytes;
	std::memcpy(ip_bytes.data(), handshake->remote_ip, ip_bytes.size());
	reported_peer_address_ = Adr(ip_bytes);

	return true;
}

void connection::complete_connection(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error || lifecycle_ != connecting) {
		if (lifecycle_ != cleanup) {
			disconnect();
			stillborn();
		}
		return;
	}
	
	bool success;

	if (link_.socket.remote_endpoint().address().is_v4())
		success = do_parse_handshake<ip::address_v4>();
	else
		success = do_parse_handshake<ip::address_v6>();

	if (!success) {
		link_.socket.close();
		DLOG(INFO) << "Error parsing handshake";
		return;
	}

#ifdef SIMULATION
	boost::uint8_t port[2];
	u16(port, incoming_port_);
	remote_identity_ = network_key(const_buffer(port, 2));
#else
	remote_identity_ = network_key(link_.socket.remote_endpoint().address());
#endif

	lifecycle_ = connected;
	established_ = boost::posix_time::second_clock::universal_time();
	node_.register_connection(shared_from_this());

	if (accepts_ib_traffic())
		outstanding_non_packet_frames_ |= frame_bit_successor_request;
	receive_next_frame();
	send_next_frame();
}

void connection::send(const packet::ptr_t pkt)
{
	// content is detached but it is small enough to send attached
	// instead of sending this packet we will start up a local request for the content
	// then send it attached
	if (pkt->content_status() == packet::content_detached && pkt->sources()->size <= oob_threshold()) {
		node_.get_protocol(pkt).new_content_request(pkt->source(), pkt->destination());
		return;
	}

	// content is attached but it's too big for this peer's oob threshold, detach it and list ourselves as a source
	if (pkt->content_status() == packet::content_attached && buffer_size(pkt->payload()->get()) > oob_threshold() && pkt->destination() != remote_id()) {
		content_sources::ptr_t self_source(new content_sources(buffer_size(pkt->payload()->get())));
		self_source->sources.insert(std::make_pair(node_.public_endpoint(), content_sources::source()));
		pkt->detach_content(self_source);
	}

	send_queue_.push_back(queued_packet::message(pkt));

	if (!outstanding_non_packet_frames_ && send_queue_.size() == 1 && lifecycle_ == connected) {
		send_next_frame();
	}
	else
		DLOG(INFO) << "Queued packet from " << std::string(node_.id()) << " to " << std::string(remote_id());
}

void connection::send(const frame_fragment::ptr_t frag)
{
	send_queue_.push_back(queued_packet::message(frag));

	if (!outstanding_non_packet_frames_ && send_queue_.size() == 1 && lifecycle_ == connected)
		send_next_frame();
}

void connection::content_sent(const boost::system::error_code& error, std::size_t bytes_transfered)
{
	if (!error && link_.socket.is_open()) {

	//	DLOG(INFO) << std::string(node_.id()) << " Sent " << bytes_transfered << " bytes of content";

		ack_queue_.push_back(pending_ack(send_queue_.front().entered, bytes_transfered));
		send_queue_.pop_front();

		send_next_frame();
	}
	else {
		DLOG(INFO) << std::string(node_.id()) << " Failed sending packet";
		if (lifecycle_ != cleanup) {
			lifecycle_ = disconnecting;
			link_.socket.shutdown(ip::tcp::socket::shutdown_send);
			node_.send_failure(shared_from_this());
			redispatch_send_queue();
		}
	}
}

void connection::receive_next_frame()
{
	update_oob_threshold();

	if (link_.valid_recv_bytes) {
		transfer_outstanding_ = true;
		frame_head_received(boost::system::error_code(), 0);
	}
	else {
		transfer_outstanding_ = false;
		boost::asio::async_read(link_.socket,
		                        mutable_buffers_1(buffer(link_.receive_buffer)),
		                        boost::asio::transfer_at_least(4),
		                        boost::bind(&connection::frame_head_received,
		                                    shared_from_this(),
		                                    placeholders::error,
		                                    placeholders::bytes_transferred));
	}
}

void connection::frame_head_received(const boost::system::error_code& error, std::size_t bytes_transfered)
{
	if (error || lifecycle_ != connected) {
		DLOG(INFO) << "Error receiving frame";
		node_.receive_failure(shared_from_this());
		return;
	}

	link_.valid_recv_bytes += bytes_transfered;

//	DLOG(INFO) << "Recieved " << bytes_transfered << " bytes, total buffered: " << link_.valid_recv_bytes;

	while (link_.valid_recv_bytes)
	{
		switch (link_.receive_buffer[0])
		{
		case frame_network_packet:
			{
	//			DLOG(INFO) << "Receiving network packet frame";
				packet::ptr_t pkt(new packet());
				pkt->receive(link_, boost::protect(boost::bind(&connection::incoming_packet, shared_from_this(), _1, _2)));
				return;
			}
		case frame_oob_threshold_update:
			if (link_.valid_recv_bytes >= oob_threshold_size()) {
				parse_oob_threshold();
				break;
			}

			boost::asio::async_read(link_.socket,
			                        mutable_buffers_1(buffer(link_.receive_buffer) + link_.valid_recv_bytes),
			                        boost::asio::transfer_at_least(oob_threshold_size()),
			                        boost::bind(&connection::frame_head_received,
			                                    shared_from_this(),
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
			return;

		case frame_successor_request:
			{
				if (link_.valid_recv_bytes >= 4) {
					int previously_outstanding = outstanding_non_packet_frames_;
					outstanding_non_packet_frames_ |= frame_bit_successor;
					if (!(previously_outstanding || send_queue_.size()))
						send_next_frame();

					link_.consume_receive_buffer(4);

					break;
				}

				boost::asio::async_read(link_.socket,
				                        mutable_buffers_1(buffer(link_.receive_buffer) + link_.valid_recv_bytes),
				                        boost::asio::transfer_at_least(4 - link_.valid_recv_bytes),
				                        boost::bind(&connection::frame_head_received,
				                                    shared_from_this(),
				                                    placeholders::error,
				                                    placeholders::bytes_transferred));

				return;
			}

		case frame_successor:
			if (link_.valid_recv_bytes >= successor_size()) {
				parse_successor();
				break;
			}

			boost::asio::async_read(link_.socket,
			                        mutable_buffers_1(buffer(link_.receive_buffer) + link_.valid_recv_bytes),
			                        boost::asio::transfer_at_least(oob_threshold_size()),
			                        boost::bind(&connection::frame_head_received,
			                                    shared_from_this(),
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
			return;

		case frame_fragment:
			{
				::frame_fragment::ptr_t frag(new ::frame_fragment());
				frag->receive(link_, boost::protect(boost::bind(&connection::incoming_fragment, shared_from_this(), _1, _2)));
				return;
			}

		default:
			{
				DLOG(INFO) << "Unknown frame type: " << link_.receive_buffer[0];
				google::FlushLogFiles(google::INFO);
				node_.receive_failure(shared_from_this());
				return;
			}
		}
	}

	receive_next_frame();
}

void connection::incoming_packet(packet::ptr_t pkt, std::size_t payload_size)
{
	if (!payload_size)
		receive_next_frame();
	node_.incoming_packet(shared_from_this(), pkt, payload_size);
}

void connection::incoming_fragment(frame_fragment::ptr_t frag, std::size_t payload_size)
{
	if (!payload_size)
		receive_next_frame();
	node_.incoming_fragment(shared_from_this(), frag, payload_size);
}

std::size_t connection::oob_threshold_size()
{
	return sizeof(oob_threshold_frame);
}

void connection::parse_oob_threshold()
{
	// OOB threshold updates double as an ACK for content related messages (network packets, fragments)
	// This is strictly for timing purposes. Idealy we could use the TCP ack for this but operating systems
	// don't provide that capability.
	if (!ack_queue_.empty()) {
		boost::posix_time::time_duration queued_duration = boost::posix_time::microsec_clock::universal_time() - ack_queue_.front().entered;
		double oob_exp = 1.0 / ( local_oob_threshold_ / ack_queue_.front().bytes_transfered + 1.0 );
		local_oob_threshold_ *= std::pow(double(queued_duration.total_milliseconds()) / double(target_latency.total_milliseconds()), oob_exp);
		ack_queue_.pop_front();
	}

	oob_threshold_frame* frame = reinterpret_cast<oob_threshold_frame*>(link_.receive_buffer.data());
	remote_oob_threshold_ = u32(frame->oob_threshold);

	link_.consume_receive_buffer(sizeof(oob_threshold_frame));
}

std::size_t connection::successor_size()
{
	if (link_.socket.remote_endpoint().address().is_v4())
		return sizeof(successor_frame<ip::address_v4>);
	else
		return sizeof(successor_frame<ip::address_v6>);
}

template <typename Addr>
std::size_t do_parse_successor(boost::uint8_t* buf, ip::tcp::endpoint& ep)
{
	successor_frame<Addr>* frame = reinterpret_cast<successor_frame<Addr>*>(buf);

	typename Addr::bytes_type ip_bytes;
	std::memcpy(ip_bytes.data(), frame->sucessor_ip, ip_bytes.size());
	ep.address(Addr(ip_bytes));
	ep.port(u16(frame->sucessor_port));

	return sizeof(successor_frame<Addr>);
}

void connection::parse_successor()
{
	ip::tcp::endpoint successor;

	std::size_t consumed;
	if (link_.socket.remote_endpoint().address().is_v4())
		consumed = do_parse_successor<ip::address_v4>(link_.receive_buffer.data(), successor);
	else
		consumed = do_parse_successor<ip::address_v6>(link_.receive_buffer.data(), successor);

	link_.consume_receive_buffer(consumed);

	DLOG(INFO) << incoming_port_ << ": Got Successor: " << successor.address() << ':' << successor.port();

#if 0
	if (successor.port() == remote_endpoint().port())
		sim.verify_reverse_successor(node_.id(), remote_id());
#endif
	node_.make_connection(successor);
}

template <typename Addr>
std::size_t do_generate_successor_frame(net_link& link, const Addr& sucessor_address, boost::uint16_t sucessor_port)
{
	successor_frame<Addr>* frame = reinterpret_cast<successor_frame<Addr>*>(link.send_buffer.data());

	frame->type = connection::frame_successor;

	typename Addr::bytes_type peer_ip = sucessor_address.to_bytes();
	std::memcpy(frame->sucessor_ip, peer_ip.data(), peer_ip.size());
	u16(frame->sucessor_port, sucessor_port);

	return sizeof(successor_frame<Addr>);
}

void connection::send_next_frame()
{
	if (outstanding_non_packet_frames_ & frame_bit_oob_threshold_update) {
		oob_threshold_frame* frame = reinterpret_cast<oob_threshold_frame*>(link_.send_buffer.data());
		frame->type = frame_oob_threshold_update;
		u32(frame->oob_threshold, local_oob_threshold_);
		boost::asio::async_write(link_.socket,
		                         mutable_buffers_1(buffer(link_.send_buffer, sizeof(oob_threshold_frame))),
		                         boost::bind(&connection::frame_sent,
		                                     shared_from_this(),
		                                     frame_bit_oob_threshold_update,
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
	}
	else if (outstanding_non_packet_frames_ & frame_bit_successor_request) {
		boost::uint8_t* frame = reinterpret_cast<boost::uint8_t*>(link_.send_buffer.data());
		*frame = frame_successor_request;
		boost::asio::async_write(link_.socket,
								 mutable_buffers_1(buffer(link_.send_buffer, 4)),
		                         boost::bind(&connection::frame_sent,
		                                     shared_from_this(),
		                                     frame_bit_successor_request,
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
		DLOG(INFO) << std::string(node_.id()) << " Wrote " << 4 << " bytes to socket";
	}
	else if (outstanding_non_packet_frames_ & frame_bit_successor) {
		ip::tcp::endpoint successor = node_.reverse_sucessor_endpoint(remote_identity_);

		std::size_t frame_size;
		if (successor.address().is_v4())
			frame_size = do_generate_successor_frame(link_, successor.address().to_v4(), successor.port());
		else
			frame_size = do_generate_successor_frame(link_, successor.address().to_v6(), successor.port());
		
		boost::asio::async_write(link_.socket,
								 mutable_buffers_1(buffer(link_.send_buffer, frame_size)),
		                         boost::bind(&connection::frame_sent,
		                                     shared_from_this(),
		                                     frame_bit_successor,
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
		DLOG(INFO) << std::string(node_.id()) << " Wrote " << frame_size << " bytes to socket";
	}
	else if (send_queue_.size()) {
		DLOG(INFO) << "Sending packet from " << std::string(node_.id()) << " to " << std::string(remote_id());

		send_queue_.front().send(link_, oob_threshold(), boost::bind(&connection::content_sent, shared_from_this(), placeholders::error, placeholders::bytes_transferred));
	}
}

void connection::frame_sent(frame_bits frame_bit, const boost::system::error_code& error, std::size_t bytes_transfered)
{
//	DLOG(INFO) << "Sent " << bytes_transfered << " bytes for frame type " << frame_bit;
	outstanding_non_packet_frames_ &= ~frame_bit;

	if (error) {
		if (lifecycle_ == connected) {
			lifecycle_ = disconnecting;
			link_.socket.shutdown(ip::tcp::socket::shutdown_send);
			node_.send_failure(shared_from_this());
			redispatch_send_queue();
		}
		return;
	}

	send_next_frame();
}

void connection::disconnect()
{
	if (link_.socket.is_open()) {
		boost::system::error_code error;
		link_.socket.shutdown(ip::tcp::socket::shutdown_both, error);
		link_.socket.close();
	}

	if (lifecycle_ != cleanup) {
		redispatch_send_queue();
		lifecycle_ = cleanup;
	}
}

void connection::redispatch_send_queue()
{
	// We don't want to re-dispatch if we are already in cleanup because
	// the node may have been destroyed
	if (lifecycle_ != cleanup) {
		for (std::deque<queued_packet>::iterator it = send_queue_.begin(); it != send_queue_.end(); ++it) {
			if (it->msg.type() == typeid(packet::ptr_t)) {
				packet::ptr_t pkt(boost::get<packet::ptr_t>(it->msg));
				if (pkt->is_direct())
					// this was a direct request, turn it into an error so the requester gets notified
					pkt->to_reply(packet::not_found);
				node_.dispatch(pkt);
			}
			else {
				// fragments are always direct so unconditionaly reply with an error
				::frame_fragment::ptr_t frag(boost::get<::frame_fragment::ptr_t>(it->msg));
				frag->to_reply();
				node_.fragment_received(shared_from_this(), frag);
			}
		}
	}
	send_queue_.clear();
}
