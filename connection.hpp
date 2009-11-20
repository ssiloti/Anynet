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
	const static boost::posix_time::time_duration target_latency;
	friend class packet;
public:
	typedef boost::shared_ptr<connection> ptr_t;
	typedef boost::weak_ptr<connection> weak_ptr_t;

	enum routing_type
	{
		oob = 0,  // out-of-band (does not send or receive in-band traffic)
		gw,       // gateway (sends but does not receive in-band traffic)
		rsvd,     // reserved
		ib        // in-band (sends and receives in-band traffic)
	};

	enum lifecycle
	{
		connecting,
		connected,
		disconnecting,
		cleanup
	};

	enum frame_types
	{
		frame_network_packet = 0,
		frame_fragment,
		frame_oob_threshold_update,
		frame_successor_request,
		frame_successor
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
	bool is_transfer_outstanding() const { return transfer_outstanding_ || send_queue_.size() > 0; }

	void send_reverse_successor()
	{
		int previously_outstanding = outstanding_non_packet_frames_;
		outstanding_non_packet_frames_ |= frame_bit_successor;
		if (!(previously_outstanding || send_queue_.size()))
			send_next_frame();
	}

	void request_reverse_successor()
	{
		int previously_outstanding = outstanding_non_packet_frames_;
		outstanding_non_packet_frames_ |= frame_bit_successor_request;
		if (!(previously_outstanding || send_queue_.size()))
			send_next_frame();
	}

	void disconnect();

	void send(const packet::ptr_t pkt);
	void send(const frame_fragment::ptr_t frag);

	template <typename Message, typename Payload, typename Handler>
	void receive_payload(Message msg, Payload payload, Handler handler)
	{
		msg->receive_payload(link_, payload, boost::protect(boost::bind(&connection::payload_received<Message, Handler>, shared_from_this(), handler, _1)));
	}

	static ptr_t connect(local_node& node, ip::tcp::endpoint peer, routing_type rtype);

	static void accept(local_node& node, ip::tcp::acceptor& incoming)
	{
		ptr_t con(new connection(node, ib));
		con->starting_connection();
		incoming.async_accept( con->link_.socket, boost::bind(&connection::connection_accepted,
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
		typedef boost::variant<packet::ptr_t, frame_fragment::ptr_t> message;
		queued_packet(message m) : msg(m), entered(boost::posix_time::microsec_clock::universal_time()) {}
		message msg;
		boost::posix_time::ptime entered;

		template <typename Handler>
		void send(net_link& link, std::size_t oob_threshold, Handler handler)
		{
			if (msg.type() == typeid(packet::ptr_t)) {
				packet::ptr_t pkt(boost::get<packet::ptr_t>(msg));
				DLOG(INFO) << "Content status: " << pkt->content_status() << " Destination: " << std::string(pkt->destination()) << " Source: " << std::string(pkt->source());
				boost::asio::async_write(link.socket, pkt->serialize(buffer(link.send_buffer)), handler);
			}
			else {
				frame_fragment::ptr_t frag = boost::get<frame_fragment::ptr_t>(msg);
				frag->trim_to(oob_threshold);
				boost::asio::async_write(link.socket, frag->serialize(buffer(link.send_buffer)), handler);
			}
		}
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
	void content_sent(const boost::system::error_code& error, std::size_t bytes_transfered);
	void redispatch_send_queue();

	void frame_head_received(const boost::system::error_code& error, std::size_t bytes_transfered);
	void incoming_packet(packet::ptr_t pkt, std::size_t payload_size);
	void incoming_fragment(frame_fragment::ptr_t, std::size_t payload_size);
	void receive_next_frame();

	template <typename Message, typename Handler>
	void payload_received(Handler handler, Message msg)
	{
		if (msg)
			receive_next_frame();
		handler(msg);
	}

	std::size_t oob_threshold_size();
	void parse_oob_threshold();

	std::size_t successor_size();
	void parse_successor();

	void send_next_frame();
	void frame_sent(frame_bits frame_bit, const boost::system::error_code& error, std::size_t bytes_transfered);

	void update_oob_threshold()
	{
		int previously_outstanding = outstanding_non_packet_frames_;
		outstanding_non_packet_frames_ |= frame_bit_oob_threshold_update;
		oob_threshold_ = std::min(remote_oob_threshold_, local_oob_threshold_);
		if (oob_threshold_ < min_oob_threshold)
			oob_threshold_ = min_oob_threshold;
		if (!(previously_outstanding || send_queue_.size()))
			send_next_frame();
	//	oob_threshold_ = 0;
	}

	//void packet_sent(const boost::system::error_code& error, std::size_t bytes_transferred);

	void connection_accepted(const boost::system::error_code& error, ip::tcp::acceptor& incoming);
	void write_handshake(const boost::system::error_code& error);
	void read_handshake(const boost::system::error_code& error, std::size_t bytes_transferred);
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
	network_key remote_identity_;
	ip::address reported_peer_address_;
	std::deque<queued_packet> send_queue_;
	std::deque<pending_ack> ack_queue_;
	boost::uint16_t incoming_port_;
	boost::posix_time::ptime established_;
	routing_type routing_type_;
	lifecycle lifecycle_;
	packet::ptr_t pending_recv_;
	bool transfer_outstanding_;
	int outstanding_non_packet_frames_;
};

#endif
