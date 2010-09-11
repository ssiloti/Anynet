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

#include "signature_scheme.hpp"
#include "packet.hpp"
#include "fragment.hpp"
#include "core.hpp"
#include <boost/function.hpp>
#include <boost/optional.hpp>
#include <vector>

class local_node;

class user_content_request
{
public:
	typedef boost::function<void(const_payload_buffer_ptr)> keyed_handler_t;

	user_content_request(const keyed_handler_t& handler) : receiving_content_(false), direct_request_pending_(false) { add_handler(handler); }
	user_content_request() : receiving_content_(false), direct_request_pending_(false) {}

	bool snoop_packet(local_node& node, packet::ptr_t pkt);
	const_payload_buffer_ptr snoop_fragment(local_node& node, const network_key& src, frame_fragment::ptr_t frag);
	void add_handler(const keyed_handler_t& handler) { handlers_.push_back(handler); }
	bool timeout(local_node& node, packet::ptr_t pkt);

	void initiate_request(signature_scheme_id sig, const content_identifier& key, local_node& node, content_size_t content_size);

	framented_content::fragment_buffer get_fragment_buffer(std::size_t offset, std::size_t size);

private:
	content_size_t content_size_;
	std::vector<keyed_handler_t> handlers_;
	boost::shared_ptr<content_sources> sources_;
	bool direct_request_pending_;
	network_key direct_request_peer_;
	boost::optional<framented_content> partial_content_;
	network_key last_indirect_request_peer_;
	bool receiving_content_;
};

class user_content : public fragmented_protocol
{
	typedef std::map<content_identifier, boost::shared_ptr<crumb> > crumbs_t;

public:
	virtual void prune_hunk(const content_identifier& id) {}

	virtual void receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);
	virtual void incoming_fragment(connection::ptr_t con, frame_fragment::ptr_t frag, std::size_t payload_size);

	virtual payload_buffer_ptr get_payload_buffer(std::size_t size) { return payload_buffer_ptr(); }
	framented_content::fragment_buffer get_fragment_buffer(frame_fragment::ptr_t frag);

	void new_content_request(const content_identifier& key, content_size_t content_size = 0, const user_content_request::keyed_handler_t& handler = user_content_request::keyed_handler_t());
	void new_content_store(content_identifier cid, const_payload_buffer_ptr hunk);

	virtual void to_content_location_failure(packet::ptr_t pkt);
	virtual void request_from_location_failure(packet::ptr_t pkt);

	void content_fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag);

	virtual void snoop_fragment(const network_key& src, frame_fragment::ptr_t frag);

	virtual void shutdown() { signature_scheme::shutdown(); vacume_sources_.cancel(); response_handlers_.clear(); }

protected:
	user_content(local_node& node, signature_scheme_id p);

	virtual void snoop_packet_payload(packet::ptr_t pkt);

	virtual const_payload_buffer_ptr get_content(const content_identifier& key) { return const_payload_buffer_ptr(); }
	virtual void store_content(hunk_descriptor_t desc, const_payload_buffer_ptr content) {}
	virtual content_identifier content_id(const_payload_buffer_ptr content) { return content_identifier(); }

private:
	struct response_handler
	{
		response_handler(boost::asio::io_service& ios)
			: timeout(ios) { timeout.expires_from_now(boost::posix_time::seconds(5)); }
		user_content_request request;
		boost::asio::deadline_timer timeout;
	};

	typedef std::map<content_identifier, boost::shared_ptr<response_handler> > response_handlers_t;

	void remove_response_handler(content_identifier key, const boost::system::error_code& error);
	void vacume_sources(const boost::system::error_code& error = boost::system::error_code());

	void content_received(connection::ptr_t con, packet::ptr_t pkt);

	response_handlers_t response_handlers_;
};

#endif
