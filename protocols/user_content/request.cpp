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

#include "payload_content_buffer.hpp"
#include "content_protocol.hpp"
#include "request.hpp"
#include <payload_request.hpp>
#include <node.hpp>
#include <boost/make_shared.hpp>

using namespace user_content;

void content_request::initiate_request(protocol_id protocol,
                                       const content_identifier& key,
                                       local_node& node,
                                       content_size_t content_size)
{
	last_indirect_request_peer_ = node.id();
	content_size_ = content_size;

	packet::ptr_t pkt(boost::make_shared<packet>());
	pkt->protocol(protocol);
	pkt->source(node.id());
	pkt->destination(key.publisher);
	pkt->name(key.name);
	pkt->content_status(packet::content_requested);
	pkt->payload(boost::make_shared<payload_request>(content_size_));

	connection::ptr_t con = node.local_request(pkt, key.publisher);

	if (con)
		last_indirect_request_peer_ = con->remote_id() - 1;
}

bool content_request::snoop_packet(content_protocol& manager, packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_attached:
		if (direct_request_pending_)
			manager.stop_direct_request(pkt->content_id());
		for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
			(*handler)(pkt->payload_as<payload_content_buffer>()->payload);
		return true;
	case packet::content_detached:
		{
			boost::shared_ptr<content_sources> sources = *pkt->payload_as<content_sources::ptr_t>();
			if (!direct_request_pending_) {
				// For now we can't download content which is larger than size_t
				// this would require modifications in the hunk store to do partial mapping
				if (sources->size > std::numeric_limits<std::size_t>::max()) {
					for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
						(*handler)(const_payload_buffer_ptr());
					return true;
				}
				manager.start_direct_request(pkt->content_id(), sources);
				direct_request_pending_ = true;
			}
			return false;
		}
	case packet::content_failure:
		if (!direct_request_pending_) {
			pkt->destination(pkt->source());
			pkt->source(manager.node_.id());
			pkt->content_status(packet::content_requested);
			pkt->payload(boost::make_shared<payload_request>(content_size_));

			connection::ptr_t con = manager.node_.local_request(pkt, last_indirect_request_peer_);

			if (con) {
				DLOG(INFO) << "Retrying content_request for " << std::string(pkt->destination()) << " to " << std::string(con->remote_id()) << " with inner id " << std::string(last_indirect_request_peer_);
				last_indirect_request_peer_ = con->remote_id() - 1;
				return false;
			}
			else {
				google::FlushLogFiles(google::INFO);
				for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
					(*handler)(const_payload_buffer_ptr());
				return true;
			}
		}
		else
			return false;
	default:
		return false;
	}
}

bool content_request::timeout(content_protocol& manager, packet::ptr_t pkt)
{
	if (direct_request_pending_)
		return false;

	return snoop_packet(manager, pkt);
}

