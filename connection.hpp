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

#ifndef CONNECTION_HPP
#define CONNECTION_HPP

#include <glog/logging.h>

#include "packet.hpp"
#include "fragment.hpp"
#include "link.hpp"
#include "core.hpp"
#include <boost/asio/write.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/bind.hpp>
#include <boost/utility.hpp>
#include <deque>

class local_node;

class connection : public boost::enable_shared_from_this<connection>, boost::noncopyable
{
	const static int min_oob_threshold = 8000;
	const static boost::posix_time::millisec target_latency;
public:
	typedef boost::shared_ptr<connection> ptr_t;
	typedef boost::weak_ptr<connection> weak_ptr_t;

	enum routing_type
	{
		oob = 0,  // out-of-band (does not send or receive in-band traffic)
		gw,       // gateway (sends but does not receive in-band traffic)
		rsvd,     // reserved
		ib,       // in-band (sends and receives in-band traffic)
	};

	enum lifecycle
	{
		connecting,
		connected,
		disconnecting,
		cleanup,
	};

	enum frame_types
	{
		frame_network_packet = 0,
		frame_fragment,
		frame_oob_threshold_update,
		frame_successor_request,
		frame_successor,
	};

	enum frame_bits
	{
		frame_bit_oob_threshold_update = 0x1,
		frame_bit_successor_request    = 0x2,
		frame_bit_successor            = 0x4,
	};

	const network_key& remote_id() const { return remote_identity_; }
	ip::tcp::endpoint remote_endpoint() const;
	ip::address reported_node_address() const { return reported_peer_address_; }
	std::size_t oob_threshold() const { return oob_threshold_; }
	bool accepts_ib_traffic() const { return routing_type_ & 0x01; }
	bool is_connected() const { return lifecycle_ == connected; }
	boost::posix_time::time_duration age() { return boost::posix_time::second_clock::universal_time() - established_; }
	bool is_transfer_outstanding() const { return transfer_outstanding_ || outstanding_non_packet_frames_ || !packet_queue_.empty() || !fragment_queue_.empty(); }
	bool supports_protocol(signature_scheme_id p) { return std::find(supported_protocols_.begin(), supported_protocols_.end(), p) != supported_protocols_.end(); }

	void send_reverse_successor()
	{
		send_next_frame(frame_bit_successor);
	}

	void request_reverse_successor()
	{
		send_next_frame(frame_bit_successor_request);
	}

	void disconnect();

	void send(packet::ptr_t pkt);
	void send(frame_fragment::ptr_t frag);

	template <typename Handler>
	void receive_payload(std::size_t payload_size, Handler handler)
	{
		if (payload_size > link_.valid_received_bytes()) {
			boost::asio::async_read(link_.socket,
			                        mutable_buffers_1(link_.receive_buffer(payload_size)),
			                        boost::asio::transfer_at_least(payload_size - link_.valid_received_bytes()),
			                        boost::bind(&connection::payload_received<Handler>,
			                                    shared_from_this(),
			                                    handler,
			                                    payload_size,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
			link_.consume_receive_buffer(link_.valid_received_bytes());
		}
		else {
			payload_received(handler, payload_size, boost::system::error_code(), 0);
		}
	}

	template <typename Handler>
	void receive_payload(std::vector<mutable_buffer> bufs, Handler handler)
	{
		std::vector<mutable_buffer>::iterator begin = bufs.begin();
		while (begin != bufs.end()) {
			std::size_t consumed = std::min(link_.valid_received_bytes(), buffer_size(*begin));
			DLOG(INFO) << "Consuming " << consumed;
			std::memcpy(buffer_cast<void*>(*begin),
			            buffer_cast<const void*>(link_.received_buffer()),
			            consumed);
			link_.consume_receive_buffer(consumed);
			if (consumed == buffer_size(*begin))
				++begin;
			else {
				(*begin) = (*begin) + consumed;
				break;
			}
		}

		if (begin != bufs.end()) {
			bufs.erase(bufs.begin(), begin);
			boost::asio::async_read(link_.socket,
			                        bufs,
			                        boost::bind(&connection::payload_received<Handler>,
			                                    shared_from_this(),
			                                    handler,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
		}
		else {
			payload_received(handler, boost::system::error_code(), 0);
		}
	}

	template <typename Message, typename Payload, typename Handler>
	void receive_payload(Message msg, Payload payload, Handler handler)
	{
		msg->receive_payload(link_,
		                     payload,
		                     boost::protect(boost::bind(&connection::payload_received<Handler>,
		                                                shared_from_this(),
		                                                handler,
		                                                const_buffer(),
		                                                placeholders::error,
		                                                placeholders::bytes_transferred)));
	}

	std::size_t discard_payload(std::size_t bytes)
	{
		std::size_t consumable = std::min(bytes, link_.valid_received_bytes());
		link_.consume_receive_buffer(consumable);
		return consumable;
	}

	static ptr_t connect(local_node& node, ip::tcp::endpoint peer, routing_type rtype);

	static void accept(local_node& node, ip::tcp::acceptor& incoming)
	{
		ptr_t con(new connection(node, ib));
		con->starting_connection();
		incoming.async_accept( con->link_.socket.lowest_layer(),
		                       boost::bind(&connection::connection_accepted,
		                                   con,
		                                   placeholders::error,
		                                   boost::ref(incoming)) );
	}

private:
	
	connection(local_node& node, routing_type rtype);
	void starting_connection();
	void stillborn();

private:
	struct queued_packet
	{
		queued_packet(content_frame::ptr_t m) : msg(m), entered(boost::posix_time::microsec_clock::universal_time()) {}
		content_frame::ptr_t msg;
		boost::posix_time::ptime entered;
	};

	struct pending_ack
	{
		pending_ack(boost::posix_time::ptime e, std::size_t b) : entered(e), bytes_transfered(b) {}
		boost::posix_time::ptime entered;
		std::size_t bytes_transfered;
	};

	union non_packet_frames
	{
		int any;
		struct type
		{
			int oob_threshold:1;
			int reverse_successor_request:1;
			int reverse_successor:1;
		};
	};

	const_buffer generate_handshake();
	bool parse_handshake();
	void redispatch_send_queue();

	void frame_head_received(const boost::system::error_code& error, std::size_t bytes_transfered);
	void incoming_packet(packet::ptr_t pkt, std::size_t payload_size);
	void incoming_fragment(frame_fragment::ptr_t, std::size_t payload_size);
	void receive_next_frame();

	template <typename Handler>
	void payload_received(Handler handler, const boost::system::error_code& error, std::size_t bytes_transfered)
	{
		if (!error) {
			DLOG(INFO) << "Received " << bytes_transfered << " bytes";
			handler();
			receive_next_frame();
		}
		else {
			node_.receive_failure(shared_from_this());
		}
	}

	template <typename Handler>
	void payload_received(Handler handler, std::size_t payload_size, const boost::system::error_code& error, std::size_t bytes_transfered)
	{
		if (!error) {
			link_.received(bytes_transfered);
			handler(buffer(link_.received_buffer(), payload_size));
			link_.consume_receive_buffer(payload_size);
			receive_next_frame();
		}
		else {
			node_.receive_failure(shared_from_this());
		}
	}

	std::size_t oob_threshold_size();
	void parse_oob_threshold();
	void update_local_threshold(boost::posix_time::time_duration duration, std::size_t bytes_sent);

	void update_oob_threshold()
	{
		oob_threshold_ = std::min(remote_oob_threshold_, local_oob_threshold_);
		if (oob_threshold_ < min_oob_threshold)
			oob_threshold_ = min_oob_threshold;
		send_next_frame(frame_bit_oob_threshold_update);
	//	oob_threshold_ = 0;
	}

	std::size_t successor_size();
	void parse_successor();

	void send_next_frame(int send_non_packet_frame);
	void send_next_frame();
	void packet_sent(const boost::system::error_code& error, std::size_t bytes_transfered);
	void fragment_sent(const boost::system::error_code& error, std::size_t bytes_transfered);
	void frame_sent(frame_bits frame_bit, const boost::system::error_code& error, std::size_t bytes_transfered);

	//void packet_sent(const boost::system::error_code& error, std::size_t bytes_transferred);

	void connection_accepted(const boost::system::error_code& error, ip::tcp::acceptor& incoming);
	void ssl_handshake(boost::asio::ssl::stream_base::handshake_type type, const boost::system::error_code& error);
	void write_handshake(const boost::system::error_code& error);
	void read_handshake(const boost::system::error_code& error, std::size_t bytes_transferred);
	void handshake_received(const boost::system::error_code& error, std::size_t bytes_transferred);
	void complete_connection(const boost::system::error_code& error, std::size_t bytes_transferred);

	template <typename Adr>
	const_buffer do_generate_handshake();
	template <typename Adr>
	bool do_parse_handshake();

	local_node& node_;
	net_link link_;

	boost::uint32_t oob_threshold_;
	boost::uint32_t remote_oob_threshold_;
	boost::uint32_t local_oob_threshold_;

	boost::uint16_t incoming_port_;
	boost::posix_time::ptime established_;

	routing_type routing_type_;

	network_key remote_identity_;
	ip::address reported_peer_address_;
	std::vector<signature_scheme_id> supported_protocols_;

	std::deque<queued_packet> packet_queue_;
	std::deque<frame_fragment::ptr_t> fragment_queue_;
	std::deque<pending_ack> ack_queue_;
	int outstanding_non_packet_frames_;
	boost::posix_time::ptime fragment_sent_;

	packet::ptr_t pending_recv_;
	bool transfer_outstanding_;

	lifecycle lifecycle_;
};

#endif
