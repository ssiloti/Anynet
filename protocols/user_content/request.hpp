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

#ifndef USER_CONTENT_REQUEST_HPP
#define USER_CONTENT_REQUEST_HPP

#include "transports/trivial/trivial_transport.hpp"
#include <protocol.hpp>
#include <packet.hpp>
#include <core.hpp>

namespace user_content
{

class content_protocol;

class content_request
{
public:
	typedef boost::function<void(const_payload_buffer_ptr)> keyed_handler_t;

	content_request(const keyed_handler_t& handler) : receiving_content_(false), direct_request_pending_(false) { add_handler(handler); }
	content_request() : receiving_content_(false), direct_request_pending_(false) {}

	void initiate_request(protocol_id protocol, const content_identifier& key, local_node& node, content_size_t content_size);

	bool snoop_packet(content_protocol& manager, packet::ptr_t pkt);
	void add_handler(const keyed_handler_t& handler) { handlers_.push_back(handler); }

	bool timeout(content_protocol& manager, packet::ptr_t pkt);

	void direct_request_failure()
	{
		direct_request_pending_ = false;
	}

private:
	content_size_t content_size_;
	std::vector<keyed_handler_t> handlers_;
	bool direct_request_pending_;
	bool receiving_content_;
	network_key last_indirect_request_peer_;
};

}

#endif
