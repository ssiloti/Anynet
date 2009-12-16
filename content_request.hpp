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

#ifndef CONTENT_REQUEST_HPP
#define CONTENT_REQUEST_HPP

#include "packet.hpp"
#include "fragment.hpp"
#include "core.hpp"
#include <boost/function.hpp>
#include <boost/optional.hpp>
#include <queue>

class local_node;
class content_sources;

class content_request
{
public:
	typedef boost::function<void(const_payload_buffer_ptr)> keyed_handler_t;

	content_request(const keyed_handler_t& handler) : receiving_content_(false) { add_handler(handler); }
	content_request() : receiving_content_(false) {}

	bool snoop_packet(local_node& node, packet::ptr_t pkt);
	const_payload_buffer_ptr snoop_fragment(local_node& node, ip::tcp::endpoint src, frame_fragment::ptr_t frag);
	void add_handler(const keyed_handler_t& handler) { handlers_.push_back(handler); }
	bool timeout(local_node& node, packet::ptr_t pkt);

	void initiate_request(protocol_t protocol, const network_key& key, local_node& node, std::size_t content_size);

	framented_content::fragment_buffer get_fragment_buffer(std::size_t offset, std::size_t size);

private:
	std::size_t content_size_;
	std::vector<keyed_handler_t> handlers_;
	boost::shared_ptr<content_sources> sources_;
	ip::tcp::endpoint direct_request_pending_;
	boost::optional<framented_content> partial_content_;
	network_key last_indirect_request_peer_;
	bool receiving_content_;
};

#endif
