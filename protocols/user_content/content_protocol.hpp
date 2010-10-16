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

#ifndef USER_CONTENT_PROTOCOL_HPP
#define USER_CONTENT_PROTOCOL_HPP

#include <glog/logging.h>

#include "transports/trivial/trivial_transport.hpp"
#include "user_content_fwd.hpp"
#include "request.hpp"
#include <hunk.hpp>
#include <protocol.hpp>
#include <packet.hpp>
#include <core.hpp>
#include <boost/function.hpp>
#include <boost/optional.hpp>
#include <vector>

class local_node;

namespace user_content
{

class content_protocol : public network_protocol, public transport::trivial::upper_layer
{
	friend class content_request;
	typedef std::map<content_identifier, boost::shared_ptr<crumb> > crumbs_t;

public:
	virtual void prune_hunk(const content_identifier& id) {}

	virtual void receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);

	void new_content_request(const content_identifier& key,
	                         content_size_t content_size = 0,
	                         const content_request::keyed_handler_t& handler = content_request::keyed_handler_t());
	void new_content_store(content_identifier cid, const_payload_buffer_ptr hunk);

	packet::payload_ptr_t self_source(std::size_t content_size);

	virtual void start_direct_request(const content_identifier& cid, boost::shared_ptr<content_sources> sources) = 0;
	virtual void stop_direct_request(const content_identifier& cid) = 0;

	virtual void to_content_location_failure(packet::ptr_t pkt);
	virtual void request_from_location_failure(packet::ptr_t pkt);

	virtual void content_finished(const content_identifier& cid, const_payload_buffer_ptr content);
	virtual const_payload_buffer_ptr get_content(const content_identifier& key) { return const_payload_buffer_ptr(); }

	virtual void stop() { network_protocol::stop(); vacume_sources_.cancel(); response_handlers_.clear(); }

protected:
	content_protocol(boost::shared_ptr<local_node> node, protocol_id p, ip::tcp::endpoint public_endpoint);

	virtual void snoop_packet_payload(packet::ptr_t pkt);

	virtual void store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content) {}

private:
	struct response_handler
	{
		response_handler(boost::asio::io_service& ios)
			: timeout(ios) { timeout.expires_from_now(boost::posix_time::seconds(5)); }
		content_request request;
		boost::asio::deadline_timer timeout;
	};

	typedef std::map<content_identifier, boost::shared_ptr<response_handler> > response_handlers_t;

	void remove_response_handler(content_identifier key, const boost::system::error_code& error);
	void vacume_sources(const boost::system::error_code& error = boost::system::error_code());

	void content_received(connection::ptr_t con, packet::ptr_t pkt);

	void completed_detached_content_request(hunk_descriptor_t desc, const_payload_buffer_ptr content);

	response_handlers_t response_handlers_;
	const ip::tcp::endpoint public_transport_endpoint_;
};

} // namespace user_content

#endif
