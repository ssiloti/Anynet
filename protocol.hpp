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

#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <glog/logging.h>

#include "packet.hpp"
#include "content_request.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/cstdint.hpp>

class local_node;
class connection;

class network_protocol : public boost::enable_shared_from_this<network_protocol>
{
	friend class remote_request_handler;

	struct crumb
	{
		crumb(boost::weak_ptr<connection> c, boost::asio::io_service& ios)
			: timeout(ios), con(c) { timeout.expires_from_now(boost::posix_time::seconds(5)); }
		boost::weak_ptr<connection> con;
		boost::asio::deadline_timer timeout;
	};

	const static boost::posix_time::time_duration min_successor_source_age;

public:
	typedef boost::shared_ptr<network_protocol> ptr_t;

	struct crumb_cmp
	{
		bool operator()(std::pair<network_key, network_key> x, std::pair<network_key, network_key> y) const
		{
			if (x.first == y.first)
				return x.second < y.second;
			else
				return x.first < y.first;
		}
	};

	typedef std::map<std::pair<network_key, network_key>, boost::shared_ptr<crumb>, crumb_cmp> crumbs_t;

	virtual ~network_protocol() {}
	virtual protocol_t id() = 0;

	void snoop_packet(packet::ptr_t pkt);
	void snoop_fragment(ip::tcp::endpoint src, frame_fragment::ptr_t frag);

	virtual payload_buffer_ptr get_payload_buffer(std::size_t size) = 0;
	virtual void prune_hunk(const network_key& id) = 0;
	framented_content::fragment_buffer get_fragment_buffer(frame_fragment::ptr_t frag);
	content_sources::ptr_t get_content_sources(network_key id, std::size_t size);

	void register_handler();
	void start_vacume();

	void new_content_request(const network_key& key, const content_request::keyed_handler_t& handler = content_request::keyed_handler_t());
	bool attach_remote_request_handler(const network_key& key, const network_key& requester);

	void drop_crumb(const std::pair<network_key, network_key>& k, boost::weak_ptr<connection> c);
	boost::shared_ptr<connection> pickup_crumb(const std::pair<network_key, network_key>& k, const boost::system::error_code& error = boost::system::error_code());
	boost::shared_ptr<connection> get_crumb(const std::pair<network_key, network_key>& k);

	void shutdown() { shutting_down_ = true; vacume_sources_.cancel(); response_handlers_.clear(); crumbs_.clear(); }

protected:
	network_protocol(local_node& node);

	virtual const_payload_buffer_ptr get_content(const network_key& key) = 0;
	virtual void store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content) = 0;
	virtual network_key content_id(const_payload_buffer_ptr content) = 0;

	local_node& node_;
	network_key node_id;

private:
	struct remote_request_handler
	{
		remote_request_handler(network_protocol& p, network_key requester, network_key requested) : protocol_(p), requester(requester), requested(requested) {}
		void operator()(const_payload_buffer_ptr content);
		network_key requester, requested;
		network_protocol& protocol_;
	};

	struct response_handler
	{
		response_handler(boost::asio::io_service& ios)
			: timeout(ios) { timeout.expires_from_now(boost::posix_time::seconds(5)); }
		content_request request;
		boost::asio::deadline_timer timeout;
	};

	typedef std::map<network_key, boost::shared_ptr<response_handler> > response_handlers_t;
	typedef std::map<network_key, content_sources::ptr_t> content_sources_t;
	typedef std::map<network_key, boost::array<boost::posix_time::ptime, 2> > content_requests_t;

	void remove_response_handler(network_key key, const boost::system::error_code& error);

	void vacume_sources(const boost::system::error_code& error = boost::system::error_code());

	crumbs_t crumbs_;
	response_handlers_t response_handlers_;
	content_sources_t content_sources_;
	content_requests_t recent_requests_;
	boost::asio::deadline_timer vacume_sources_;
	bool shutting_down_;
};

std::size_t oob_endpoint_size(const local_node& node);
boost::uint8_t* encode_endpoint(ip::tcp::endpoint ep, boost::uint8_t* buf);
ip::tcp::endpoint decode_endpoint(const local_node& node, boost::uint8_t* buf);

#endif