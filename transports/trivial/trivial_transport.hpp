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

#ifndef TRANSPORT_TRIVIAL_HPP
#define TRANSPORT_TRIVIAL_HPP

#include "transport.hpp"
#include "content_sources.hpp"
#include "content.hpp"
#include "link.hpp"
#include "core.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <deque>

namespace transport {

class trivial : public network_transport, public boost::enable_shared_from_this<trivial>
{
public:
	struct message
	{
		protocol_id pid;

		enum payload_status
		{
			status_requested = 0,
			status_attached = 1,
			// status 2 reserved
			status_failed = 3,
		} status;

		content_identifier cid;
		const_payload_buffer_ptr payload;
	};

	friend class connection;
	class connection : public boost::enable_shared_from_this<connection>
	{
		friend class trivial;
	public:
		net_link& link() { return link_; }
		const network_key& remote_id() { return id_; }
		const ip::tcp::endpoint& remote_endpoint() { return remote_public_endpoint_; }

		connection(boost::shared_ptr<trivial> m);

		void send(const message& msg);

	private:
		const static int version = 0;

		struct queued_request
		{
			protocol_id pid;
			content_identifier cid;
		};

		void message_sent(const boost::system::error_code& error, std::size_t bytes_transferred);
		void send_next_message();

		void receive_next_message();
		void message_header_received(const boost::system::error_code& error, std::size_t bytes_transferred);
		void message_payload_received(message msg, const boost::system::error_code& error, std::size_t bytes_transferred);

		void connect(ip::tcp::endpoint ep);
		void accept(ip::tcp::acceptor& incoming);
		void stop();

		const_buffer generate_handshake();
		template <typename Adr>
		const_buffer do_generate_handshake();
		template <typename Adr>
		bool parse_handshake();

		void connection_accepted(const boost::system::error_code& error);
		void ssl_handshake(boost::asio::ssl::stream_base::handshake_type type, const boost::system::error_code& error);
		void write_handshake(const boost::system::error_code& error);
		void read_handshake(const boost::system::error_code& error, std::size_t bytes_transferred);
		void handshake_received(const boost::system::error_code& error, std::size_t bytes_transferred);

		net_link link_;
		network_key id_;
		std::deque<message> send_queue_;
		boost::shared_ptr<trivial> manager_;
		network_key remote_identity_;
		ip::tcp::endpoint remote_public_endpoint_;
		bool tx_ready_;
	};

	friend class request;
	class request
	{
	public:
		request(local_node& node, boost::shared_ptr<content_sources> sources);

		bool failure(boost::shared_ptr<trivial> manager,
		             const network_key& src,
		             protocol_id pid,
		             const content_identifier& cid);
		void start(boost::shared_ptr<trivial>, protocol_id pid, const content_identifier& cid);
		void stop();

	private:
		boost::shared_ptr<content_sources> sources_;
		network_key outstanding_request_;
		boost::asio::deadline_timer timeout_;
		bool running_;
	};

	class upper_layer
	{
	public:
		virtual payload_buffer_ptr get_payload_buffer(std::size_t size) = 0;
		virtual void content_finished(const content_identifier& cid, const_payload_buffer_ptr content) = 0;
		virtual const_payload_buffer_ptr get_content(const content_identifier& cid) = 0;
		virtual content_identifier content_id(const_buffer content) = 0;

		virtual ~upper_layer() {}
	};

	trivial(local_node& node);

	void start();
	void stop();

	ip::tcp::endpoint public_endpoint() const;
	bool is_connected(ip::tcp::endpoint ep);

	void start_request(local_node& node, protocol_id pid, const content_identifier& cid, boost::shared_ptr<content_sources> sources);
	void stop_request(protocol_id pid, const content_identifier& cid);

	void register_upper_layer(protocol_id pid, boost::shared_ptr<upper_layer> upper);

private:
	void connection_accepted(boost::shared_ptr<connection> con, const boost::system::error_code& error);
	void connection_failure(boost::shared_ptr<connection> con);
	void connection_finished(boost::shared_ptr<connection> con);

	void send(ip::tcp::endpoint ep, const message& msg);

	bool valid_protocol(protocol_id pid);
	payload_buffer_ptr get_payload_buffer(protocol_id pid, std::size_t size);

	void message_received(boost::shared_ptr<connection> con, message& msg);
	void request_timeout(const network_key& src,
	                     protocol_id pid,
	                     const content_identifier& cid,
	                     const boost::system::error_code& error);

	std::vector<boost::shared_ptr<connection> > connections_;
	std::map<protocol_id, boost::shared_ptr<upper_layer> > upper_layers_;
	std::map<std::pair<protocol_id, content_identifier>, boost::shared_ptr<request> > requests_;
	ip::tcp::acceptor acceptor_;
	bool running_;
};

}

#endif
