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

const boost::posix_time::millisec connection::target_latency(100);

template <typename Adr>
struct link_handshake
{
	boost::uint8_t sig[2];
	boost::uint8_t protocol;
	boost::uint8_t type;
	boost::uint8_t remote_ip[Adr::bytes_type::static_size];
	boost::uint8_t rsvd[2];
	boost::uint8_t incoming_port[2];
	boost::uint8_t supported_protocol_count;
	boost::uint8_t supported_protocols[1][2];
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
: node_(node), link_(node.io_service(), node.context), routing_type_(rtype), incoming_port_(0),
	lifecycle_(connecting), oob_threshold_(min_oob_threshold), local_oob_threshold_(min_oob_threshold), transfer_outstanding_(false),
	outstanding_non_packet_frames_(0)
{

}

ip::tcp::endpoint connection::remote_endpoint() const
{
	boost::system::error_code error;
	return ip::tcp::endpoint(link_.socket.lowest_layer().remote_endpoint(error).address(), incoming_port_);
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
	con->link_.socket.lowest_layer().async_connect( peer, boost::bind(&connection::ssl_handshake,
	                                                                  con,
	                                                                  boost::asio::ssl::stream_base::client,
	                                                                  placeholders::error) );
	return con;
}

void connection::connection_accepted(const boost::system::error_code& error, ip::tcp::acceptor& incoming)
{
	if (!error && lifecycle_ == connecting) {
		ptr_t con(new connection(node_, ib));
		con->starting_connection();
		incoming.async_accept( con->link_.socket.lowest_layer(),
		                       boost::bind(&connection::connection_accepted,
		                                   con,
		                                   placeholders::error,
		                                   boost::ref(incoming)) );
		
		ssl_handshake(boost::asio::ssl::stream_base::server, boost::system::error_code());
	}
	else {
		if (lifecycle_ != cleanup) {
			disconnect();
			stillborn();
		}
	}
}

void connection::ssl_handshake(boost::asio::ssl::stream_base::handshake_type type, const boost::system::error_code& error)
{
	if (error && lifecycle_ != cleanup) {
		disconnect();
		stillborn();
		return;
	}

	link_.socket.async_handshake(type, boost::bind(&connection::write_handshake, shared_from_this(), boost::asio::placeholders::error));
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
		std::size_t handshake_min_size;

		if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
			handshake_min_size = sizeof(link_handshake<ip::address_v4>);
		else
			handshake_min_size = sizeof(link_handshake<ip::address_v6>);

		boost::asio::async_read(link_.socket,
		                        mutable_buffers_1(link_.receive_buffer()),
		                        boost::asio::transfer_at_least(handshake_min_size),
		                        boost::bind(&connection::handshake_received,
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
	const std::vector<signature_scheme_id>& protocols = node_.supported_protocols();
	link_handshake<Adr>* handshake = buffer_cast<link_handshake<Adr>*>( link_.send_buffer(sizeof(link_handshake<Adr>)
	                                                                    + (protocols.size() - 1) * 2) );
	handshake->sig[0] = 'A';
	handshake->sig[1] = 'N';
	handshake->protocol = link_.protocol_version;
	handshake->type = routing_type_;

	typename Adr::bytes_type peer_ip = to<Adr>(link_.socket.lowest_layer().remote_endpoint().address()).to_bytes();
	std::memcpy(handshake->remote_ip, peer_ip.data(), peer_ip.size());

	u16(handshake->incoming_port, node_.config().listen_port());

	handshake->supported_protocol_count = protocols.size();
	for (std::vector<signature_scheme_id>::const_iterator sig = protocols.begin(); sig != protocols.end(); ++sig) {
		u16(handshake->supported_protocols[sig - protocols.begin()], *sig);
	}

	return link_.sendable_buffer();
}

const_buffer connection::generate_handshake()
{
//	DLOG(INFO) << "Generating handshake";

	if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
		return do_generate_handshake<ip::address_v4>();
	else
		return do_generate_handshake<ip::address_v6>();
}

template <typename Adr>
bool connection::do_parse_handshake()
{
//	DLOG(INFO) << "Parsing handshake";
	const link_handshake<Adr>* handshake = buffer_cast<const link_handshake<Adr>*>(link_.received_buffer());

	if (handshake->sig[0] != 'A' || handshake->sig[1] != 'N' || handshake->protocol != link_.protocol_version)
		return false;

	routing_type_ = std::min(routing_type_, connection::routing_type(handshake->type & 0x03));
	incoming_port_ = u16(handshake->incoming_port);

	typename Adr::bytes_type ip_bytes;
	std::memcpy(ip_bytes.data(), handshake->remote_ip, ip_bytes.size());
	reported_peer_address_ = Adr(ip_bytes);

	supported_protocols_.resize(handshake->supported_protocol_count);
	link_.consume_receive_buffer(sizeof(link_handshake<Adr>) - sizeof(handshake->supported_protocols));

	return true;
}

void connection::handshake_received(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error || lifecycle_ != connecting) {
		if (lifecycle_ != cleanup) {
			disconnect();
			stillborn();
		}
		return;
	}

	link_.received(bytes_transferred);

	bool handshake_valid;

	if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
		handshake_valid = do_parse_handshake<ip::address_v4>();
	else
		handshake_valid = do_parse_handshake<ip::address_v6>();

	if (!handshake_valid) {
		link_.socket.lowest_layer().close();
		DLOG(INFO) << "Error parsing handshake";
		return;
	}

	remote_identity_ = network_key(::SSL_get_peer_certificate(link_.socket.impl()->ssl));

	if (supported_protocols_.size() * 2 > link_.valid_received_bytes())
		boost::asio::async_read(link_.socket,
		                        mutable_buffers_1(link_.receive_buffer()),
		                        boost::asio::transfer_at_least(supported_protocols_.size() - link_.valid_received_bytes()),
		                        boost::bind(&connection::complete_connection,
		                                    shared_from_this(),
		                                    placeholders::error,
		                                    placeholders::bytes_transferred));
	else
		complete_connection(error, 0);
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

	link_.received(bytes_transferred);

	const boost::uint8_t (*supported_protocols)[2] = buffer_cast<const boost::uint8_t(*)[2]>(link_.received_buffer());
	for (std::vector<signature_scheme_id>::iterator sig = supported_protocols_.begin(); sig != supported_protocols_.end(); ++sig) {
		*sig = u16(supported_protocols[sig - supported_protocols_.begin()]);
	}
	link_.consume_receive_buffer(supported_protocols_.size() * 2);

	lifecycle_ = connected;

	established_ = boost::posix_time::second_clock::universal_time();
	DLOG(INFO) << "Connected with cipher: " << ::SSL_CIPHER_get_name(::SSL_get_current_cipher(link_.socket.impl()->ssl)); //<< " and compression: " << ::SSL_COMP_get_name(::SSL_get_current_compression(link_.socket.impl()->ssl));
	node_.register_connection(shared_from_this());

	if (accepts_ib_traffic())
		outstanding_non_packet_frames_ |= frame_bit_successor_request;
	send_next_frame();
	receive_next_frame();
}

void connection::send(packet::ptr_t pkt)
{
	packet_queue_.push_back(boost::static_pointer_cast<content_frame>(pkt));

	if (!outstanding_non_packet_frames_ && packet_queue_.size() == 1 && fragment_queue_.empty() && lifecycle_ == connected) {
		send_next_frame();
	}
	else
		DLOG(INFO) << "Queued packet from " << std::string(node_.id()) << " to " << std::string(remote_id());
}

void connection::send(frame_fragment::ptr_t frag)
{
	fragment_queue_.push_back(frag);

	if (!outstanding_non_packet_frames_ && packet_queue_.empty() && fragment_queue_.size() == 1 && lifecycle_ == connected)
		send_next_frame();
}

void connection::receive_next_frame()
{
	if (link_.valid_received_bytes()) {
		transfer_outstanding_ = true;
		frame_head_received(boost::system::error_code(), 0);
	}
	else {
		transfer_outstanding_ = false;
		boost::asio::async_read(link_.socket,
		                        mutable_buffers_1(link_.receive_buffer()),
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

	link_.received(bytes_transfered);

	DLOG(INFO) << std::string(node_.id()) << " Recieved " << bytes_transfered << " bytes, total buffered: " << link_.valid_received_bytes();

	while (link_.valid_received_bytes())
	{
		switch (buffer_cast<const boost::uint8_t*>(link_.received_buffer())[0])
		{
		case frame_network_packet:
			{
	//			DLOG(INFO) << "Receiving network packet frame";
				packet::ptr_t pkt(new packet());
				pkt->receive(link_, boost::protect(boost::bind(&connection::incoming_packet, shared_from_this(), _1, _2)));
				return;
			}
		case frame_oob_threshold_update:
			if (link_.valid_received_bytes() >= oob_threshold_size()) {
				parse_oob_threshold();
				break;
			}

			boost::asio::async_read(link_.socket,
			                        mutable_buffers_1(link_.receive_buffer()),
			                        boost::asio::transfer_at_least(oob_threshold_size() - link_.valid_received_bytes()),
			                        boost::bind(&connection::frame_head_received,
			                                    shared_from_this(),
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
			return;

		case frame_successor_request:
			{
				if (link_.valid_received_bytes() >= 4) {
					DLOG(INFO) << std::string(node_.id()) << "Sending successor";
					send_next_frame(frame_bit_successor);
					link_.consume_receive_buffer(4);
					break;
				}

				boost::asio::async_read(link_.socket,
				                        mutable_buffers_1(link_.receive_buffer()),
				                        boost::asio::transfer_at_least(4 - link_.valid_received_bytes()),
				                        boost::bind(&connection::frame_head_received,
				                                    shared_from_this(),
				                                    placeholders::error,
				                                    placeholders::bytes_transferred));

				return;
			}

		case frame_successor:
			if (link_.valid_received_bytes() >= successor_size()) {
				parse_successor();
				break;
			}

			boost::asio::async_read(link_.socket,
			                        mutable_buffers_1(link_.receive_buffer()),
			                        boost::asio::transfer_at_least(oob_threshold_size() - link_.valid_received_bytes()),
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
				DLOG(INFO) << "Unknown frame type: " << buffer_cast<const boost::uint8_t*>(link_.received_buffer())[0];
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
	node_.incoming_packet(shared_from_this(), pkt, payload_size);
	if (!payload_size) {
		receive_next_frame();
	}
}

void connection::incoming_fragment(frame_fragment::ptr_t frag, std::size_t payload_size)
{
	node_.incoming_fragment(shared_from_this(), frag, payload_size);
	if (!payload_size) {
		receive_next_frame();
	}
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
		update_local_threshold( boost::posix_time::microsec_clock::universal_time() - ack_queue_.front().entered, ack_queue_.front().bytes_transfered );
		ack_queue_.pop_front();
	}

	const oob_threshold_frame* frame = buffer_cast<const oob_threshold_frame*>(link_.received_buffer());
	remote_oob_threshold_ = u32(frame->oob_threshold);
	update_oob_threshold();

	link_.consume_receive_buffer(sizeof(oob_threshold_frame));
}

void connection::update_local_threshold(boost::posix_time::time_duration duration, std::size_t bytes_sent)
{
	// Move the oob threshold up or down in proportion to the difference between the target latency and
	// how long this operation took
	// We cap any increase at the amount of data sent for this operation. This is to prevent
	// the threshold from overshooting too much on lightly loaded short-thin links.
	local_oob_threshold_ += std::min(int(double((target_latency.total_milliseconds() - duration.total_milliseconds()))
	                         / double(target_latency.total_milliseconds())
	                         * double(local_oob_threshold_)), int(bytes_sent));
	update_oob_threshold();
}

std::size_t connection::successor_size()
{
	if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
		return sizeof(successor_frame<ip::address_v4>);
	else
		return sizeof(successor_frame<ip::address_v6>);
}

template <typename Addr>
std::size_t do_parse_successor(const_buffer buf, ip::tcp::endpoint& ep)
{
	const successor_frame<Addr>* frame = buffer_cast<const successor_frame<Addr>*>(buf);

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
	if (link_.socket.lowest_layer().remote_endpoint().address().is_v4())
		consumed = do_parse_successor<ip::address_v4>(link_.received_buffer(), successor);
	else
		consumed = do_parse_successor<ip::address_v6>(link_.received_buffer(), successor);

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
	successor_frame<Addr>* frame = buffer_cast<successor_frame<Addr>*>(link.send_buffer(sizeof(successor_frame<Addr>)));

	frame->type = connection::frame_successor;

	typename Addr::bytes_type peer_ip = sucessor_address.to_bytes();
	std::memcpy(frame->sucessor_ip, peer_ip.data(), peer_ip.size());
	u16(frame->sucessor_port, sucessor_port);

	return sizeof(successor_frame<Addr>);
}

void connection::send_next_frame(int send_non_packet_frame)
{
	if (!outstanding_non_packet_frames_ && packet_queue_.empty() && fragment_queue_.empty() && lifecycle_ == connected) {
		outstanding_non_packet_frames_ |= send_non_packet_frame;
		send_next_frame();
	}
	else {
		outstanding_non_packet_frames_ |= send_non_packet_frame;
	}
}

void connection::send_next_frame()
{
	link_.clear_send_buffer();

	if (outstanding_non_packet_frames_ & frame_bit_oob_threshold_update) {
		oob_threshold_frame* frame = buffer_cast<oob_threshold_frame*>(link_.send_buffer(sizeof(oob_threshold_frame)));
		frame->type = frame_oob_threshold_update;
		u32(frame->oob_threshold, local_oob_threshold_);
		boost::asio::async_write(link_.socket,
		                         const_buffers_1(link_.sendable_buffer()),
		                         boost::bind(&connection::frame_sent,
		                                     shared_from_this(),
		                                     frame_bit_oob_threshold_update,
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
	}
	else if (outstanding_non_packet_frames_ & frame_bit_successor_request) {
		boost::uint8_t* frame = buffer_cast<boost::uint8_t*>(link_.send_buffer(4));
		*frame = frame_successor_request;
		boost::asio::async_write(link_.socket,
		                         const_buffers_1(link_.sendable_buffer()),
		                         boost::bind(&connection::frame_sent,
		                                     shared_from_this(),
		                                     frame_bit_successor_request,
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
		DLOG(INFO) << std::string(node_.id()) << " Wrote " << 4 << " bytes to " << std::string(remote_id()).substr(0, 4);
	}
	else if (outstanding_non_packet_frames_ & frame_bit_successor) {
		ip::tcp::endpoint successor = node_.successor_endpoint(remote_identity_);

		if (successor.address().is_v4())
			do_generate_successor_frame(link_, successor.address().to_v4(), successor.port());
		else
			do_generate_successor_frame(link_, successor.address().to_v6(), successor.port());
		
		boost::asio::async_write(link_.socket,
		                         const_buffers_1(link_.sendable_buffer()),
		                         boost::bind(&connection::frame_sent,
		                                     shared_from_this(),
		                                     frame_bit_successor,
		                                     placeholders::error,
		                                     placeholders::bytes_transferred));
		DLOG(INFO) << std::string(node_.id()) << " Wrote " << buffer_size(link_.sendable_buffer()) << " bytes to " << std::string(remote_id()).substr(0, 4);
	}
	else if (!packet_queue_.empty()) {
		DLOG(INFO) << "Sending packet from " << std::string(node_.id()) << " to " << std::string(remote_id());

		const std::vector<const_buffer>& send_buffers = packet_queue_.front().msg->serialize(oob_threshold(), link_.send_buffer());
		std::size_t bytes_transfered = 0;
		for (std::vector<const_buffer>::const_iterator buf = send_buffers.begin(); buf != send_buffers.end(); ++buf)
			bytes_transfered += buffer_size(*buf);
		ack_queue_.push_back(pending_ack(packet_queue_.front().entered, bytes_transfered));

		assert(buffer_cast<const boost::uint8_t*>(send_buffers.front())[0] == 0);
		DLOG(INFO) << "Sending " << bytes_transfered << " bytes";

		boost::asio::async_write(link_.socket,
		                         send_buffers,
		                         boost::bind(&connection::packet_sent, shared_from_this(), placeholders::error, placeholders::bytes_transferred));
	}
	else if (!fragment_queue_.empty()) {
		DLOG(INFO) << "Sending fragment from " << std::string(node_.id()) << " to " << std::string(remote_id());

		fragment_sent_ = boost::posix_time::microsec_clock::universal_time();

		boost::asio::async_write(link_.socket,
		                         packet_queue_.front().msg->serialize(local_oob_threshold_, link_.send_buffer()),
		                         boost::bind(&connection::fragment_sent, shared_from_this(), placeholders::error, placeholders::bytes_transferred));
	}
}

void connection::packet_sent(const boost::system::error_code& error, std::size_t bytes_transfered)
{
	if (!error && link_.socket.lowest_layer().is_open()) {

		DLOG(INFO) << std::string(node_.id()) << " Sent " << bytes_transfered << " bytes of content";

		assert(buffer_cast<const boost::uint8_t*>(link_.sendable_buffer())[0] == 0);

		node_.sent_content(remote_id(), bytes_transfered);
		packet_queue_.pop_front();

		send_next_frame();
	}
	else {
		DLOG(INFO) << std::string(node_.id()) << " Failed sending packet";
		if (lifecycle_ != cleanup) {
			lifecycle_ = disconnecting;
			link_.socket.lowest_layer().shutdown(ip::tcp::socket::shutdown_send);
			node_.send_failure(shared_from_this());
			redispatch_send_queue();
		}
	}
}

void connection::fragment_sent(const boost::system::error_code& error, std::size_t bytes_transfered)
{
	if (!error && link_.socket.lowest_layer().is_open()) {

	//	DLOG(INFO) << std::string(node_.id()) << " Sent " << bytes_transfered << " bytes of content";
		update_local_threshold(boost::posix_time::microsec_clock::universal_time() - fragment_sent_, bytes_transfered);
		node_.sent_content(remote_id(), bytes_transfered);

		if (fragment_queue_.front()->size() == 0)
			fragment_queue_.pop_front();

		send_next_frame();
	}
	else {
		DLOG(INFO) << std::string(node_.id()) << " Failed sending frame";
		if (lifecycle_ != cleanup) {
			lifecycle_ = disconnecting;
			link_.socket.lowest_layer().shutdown(ip::tcp::socket::shutdown_send);
			node_.send_failure(shared_from_this());
			redispatch_send_queue();
		}
	}
}

void connection::frame_sent(frame_bits frame_bit, const boost::system::error_code& error, std::size_t bytes_transfered)
{
//	DLOG(INFO) << "Sent " << bytes_transfered << " bytes for frame type " << frame_bit;
	outstanding_non_packet_frames_ &= ~frame_bit;

	if (error) {
		if (lifecycle_ == connected) {
			lifecycle_ = disconnecting;
			link_.socket.lowest_layer().shutdown(ip::tcp::socket::shutdown_send);
			node_.send_failure(shared_from_this());
			redispatch_send_queue();
		}
		return;
	}

	send_next_frame();
}

void connection::disconnect()
{
	if (link_.socket.lowest_layer().is_open()) {
	//	link_.socket.async_shutdown(boost::bind(&connection::link_shutdown, shared_from_this()));
		boost::system::error_code error;
		link_.socket.lowest_layer().shutdown(ip::tcp::socket::shutdown_both, error);
		link_.socket.lowest_layer().close();
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
		for (std::deque<queued_packet>::iterator it = packet_queue_.begin(); it != packet_queue_.end(); ++it) {
			packet::ptr_t pkt(boost::dynamic_pointer_cast<packet>(it->msg));
			if (pkt) {
				if (pkt->is_direct())
					// this was a direct request, turn it into an error so the requester gets notified
					pkt->to_reply(packet::content_failure);
				node_.dispatch(pkt);
			}
			else {
				// fragments are always direct so unconditionaly reply with an error
				::frame_fragment::ptr_t frag(boost::dynamic_pointer_cast<::frame_fragment>(it->msg));
				frag->to_reply();
				node_.fragment_received(shared_from_this(), frag);
			}
		}
	}
	packet_queue_.clear();
}

//void connection::link_shutdown(const boost::system::error_code& error)
//{
//}
