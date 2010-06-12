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

#ifndef PROTOCOL_USER_CONTENT_HPP
#define PROTOCOL_USER_CONTENT_HPP

#include <glog/logging.h>

#include "protocol.hpp"
#include "packet.hpp"
#include "fragment.hpp"
#include "core.hpp"
#include <boost/function.hpp>
#include <boost/optional.hpp>
#include <vector>

class local_node;

struct content_sources : boost::enable_shared_from_this<content_sources>
{
	typedef boost::shared_ptr<content_sources> ptr_t;

	struct source
	{
		source() : stored(boost::posix_time::second_clock::universal_time()), active_request_count(0) {}
		source(ip::tcp::endpoint ep) : ep(ep), stored(boost::posix_time::second_clock::universal_time()) {}
		boost::posix_time::ptime stored;
		ip::tcp::endpoint ep;
		unsigned int active_request_count;
	};

	struct ep_cmp
	{
		bool operator()(const ip::tcp::endpoint& l, const ip::tcp::endpoint& r) const { if (l.address() == r.address()) return l.port() < r.port(); return l.address() < r.address(); }
	};

	typedef std::map<network_key, source> sources_t;

	content_sources(std::size_t s) : size(s), last_stat_source_count(0) {}

	sendable_payload* get_payload();

	sources_t sources;
	boost::uint32_t size;
	int last_stat_source_count; // the most recent source count which was registered with the sources_per_hunk stats
};

class content_request
{
public:
	typedef boost::function<void(const_payload_buffer_ptr)> keyed_handler_t;

	content_request(const keyed_handler_t& handler) : receiving_content_(false) { add_handler(handler); }
	content_request() : receiving_content_(false) {}

	bool snoop_packet(local_node& node, packet::ptr_t pkt);
	const_payload_buffer_ptr snoop_fragment(local_node& node, const network_key& src, frame_fragment::ptr_t frag);
	void add_handler(const keyed_handler_t& handler) { handlers_.push_back(handler); }
	bool timeout(local_node& node, packet::ptr_t pkt);

	void initiate_request(protocol_t protocol, const network_key& key, local_node& node, std::size_t content_size);

	framented_content::fragment_buffer get_fragment_buffer(std::size_t offset, std::size_t size);

private:
	std::size_t content_size_;
	std::vector<keyed_handler_t> handlers_;
	boost::shared_ptr<content_sources> sources_;
	bool direct_request_pending_;
	network_key direct_request_peer_;
	boost::optional<framented_content> partial_content_;
	network_key last_indirect_request_peer_;
	bool receiving_content_;
};

class user_content : public network_protocol
{
public:
	user_content(local_node& node, protocol_t p);

	virtual protocol_t id() { return protocol_; }
	virtual void prune_hunk(const network_key& id) {}

	virtual void receive_payload(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);
	void incoming_fragment(connection::ptr_t con, frame_fragment::ptr_t frag, std::size_t payload_size);

	virtual payload_buffer_ptr get_payload_buffer(std::size_t size) { return payload_buffer_ptr(); }
	framented_content::fragment_buffer get_fragment_buffer(frame_fragment::ptr_t frag);
	content_sources::ptr_t get_content_sources(network_key id, std::size_t size);

	void start_vacume();

	void new_content_request(const network_key& key, std::size_t content_size = 0, const content_request::keyed_handler_t& handler = content_request::keyed_handler_t());
	void new_content_store(const_payload_buffer_ptr hunk);

	virtual void to_content_location_failure(packet::ptr_t pkt);
	virtual void request_from_location_failure(packet::ptr_t pkt);

	void content_fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag);

	void snoop_fragment(const network_key& src, frame_fragment::ptr_t frag);

	virtual void shutdown() { network_protocol::shutdown(); vacume_sources_.cancel(); response_handlers_.clear(); }

protected:
	virtual void snoop_packet_payload(packet::ptr_t pkt);

	virtual const_payload_buffer_ptr get_content(const network_key& key) { return const_payload_buffer_ptr(); }
	virtual void store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content) {}
	virtual network_key content_id(const_payload_buffer_ptr content) { return network_key(); }

private:
	struct response_handler
	{
		response_handler(boost::asio::io_service& ios)
			: timeout(ios) { timeout.expires_from_now(boost::posix_time::seconds(5)); }
		content_request request;
		boost::asio::deadline_timer timeout;
	};

	typedef std::map<network_key, boost::shared_ptr<response_handler> > response_handlers_t;
	typedef std::map<network_key, content_sources::ptr_t> content_sources_t;

	void remove_response_handler(network_key key, const boost::system::error_code& error);
	void vacume_sources(const boost::system::error_code& error = boost::system::error_code());

	void content_received(connection::ptr_t con, packet::ptr_t pkt);
	void sources_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);
	void request_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);
	void failure_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);

	response_handlers_t response_handlers_;
	content_sources_t content_sources_;
	boost::asio::deadline_timer vacume_sources_;
	protocol_t protocol_;
};

#endif
