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

#include "content_request.hpp"
#include "node.hpp"

#ifdef SIMULATION
#include "simulator.hpp"
#endif

void content_request::initiate_request(protocol_t protocol, const network_key& key, local_node& node)
{
	last_indirect_request_peer_ = node.id();

	packet::ptr_t pkt(new packet());
	pkt->protocol(protocol);
	pkt->source(node.id());
	pkt->destination(key);
	pkt->content_status(packet::content_requested);
	pkt->content_size(0);

	connection::ptr_t con = node.local_request(pkt, key);

	if (con)
		last_indirect_request_peer_ = con->remote_id() - 1;
}

bool content_request::snoop_packet(local_node& node, packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_attached:
		for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
			(*handler)(pkt->payload());
		return true;
	case packet::content_detached:
		sources_ = pkt->sources();
		if (direct_request_pending_ == ip::tcp::endpoint()) {
			/*packet::ptr_t request(new packet());
			request->protocol(pkt->protocol());
			request->source(node.id());
			request->destination(pkt->source());
			request->content_status(packet::content_requested);
			node.direct_request(sources_->sources.begin()->ep, request);*/
			if (!partial_content_) {
				partial_content_ = framented_content(node.get_protocol(pkt).get_payload_buffer(sources_->size));
			}
			std::pair<std::size_t, std::size_t> range = partial_content_->next_invalid_range();
			frame_fragment::ptr_t frag(new frame_fragment(pkt->protocol(), pkt->source(), range.first, range.second));
			node.direct_request(sources_->sources.begin()->first, frag);
			direct_request_pending_ = sources_->sources.begin()->first;
		}
		return false;
	case packet::content_failure:
		if ( ( !sources_ || sources_->sources.size() == 0 ) && ( direct_request_pending_ == ip::tcp::endpoint() ) ) {

			pkt->destination(pkt->source());
			pkt->source(node.id());
			pkt->content_status(packet::content_requested);
			pkt->content_size(0);

			connection::ptr_t con = node.local_request(pkt, last_indirect_request_peer_);

			if (con) {
				DLOG(INFO) << "Retrying request for " << std::string(pkt->destination()) << " to " << std::string(con->remote_id()) << " with inner id " << std::string(last_indirect_request_peer_);
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
		else if (pkt->source() == network_key(direct_request_pending_)) {
			sources_->sources.erase(direct_request_pending_);

		/*	packet::ptr_t request(new packet());
			request->protocol(pkt->protocol());
			request->source(node.id());
			request->destination(pkt->source());
			request->content_status(packet::content_requested);
			node.direct_request(sources_->sources.begin()->ep, request);*/

			std::pair<std::size_t, std::size_t> range = partial_content_->next_invalid_range();
			frame_fragment::ptr_t frag(new frame_fragment(pkt->protocol(), pkt->source(), range.first, range.second));
			node.direct_request(sources_->sources.begin()->first, frag);
			direct_request_pending_ = sources_->sources.begin()->first;
			return false;
		}
	default:
		return false;
	}
}

const_payload_buffer_ptr content_request::snoop_fragment(local_node& node, ip::tcp::endpoint src, frame_fragment::ptr_t frag)
{
	if (!partial_content_) {
		// We got a fragment frame for something we haven't started a fragmented download on yet
		// just ignore it
		frag->to_request(0, 0);
		return const_payload_buffer_ptr();
	}

	direct_request_pending_ = ip::tcp::endpoint();

	switch (frag->status())
	{
	case frame_fragment::status_attached:
		{
			partial_content_->mark_valid(frag, src.address());

			const_payload_buffer_ptr payload = partial_content_->complete();

			if (payload) {
				network_key pid(payload->get());
				if (pid == frag->id())
					return payload;
				else
					partial_content_->reset();
			}
			break;
		}
	case frame_fragment::status_failed:
		if (sources_) {
			sources_->sources.erase(src);
			if (!sources_->sources.empty())
				src = sources_->sources.begin()->first;
			else
				return const_payload_buffer_ptr();
		}
		break;
	}

	std::pair<std::size_t, std::size_t> next_range(partial_content_->next_invalid_range());
	frag->to_request(next_range.first, next_range.second);
	direct_request_pending_ = src;

	return const_payload_buffer_ptr();
}

framented_content::fragment_buffer content_request::get_fragment_buffer(std::size_t offset, std::size_t size)
{
	if (partial_content_)
		return partial_content_->get_fragment_buffer(offset, size);
	else
		return framented_content::fragment_buffer(offset);
}

bool content_request::timeout(local_node& node, packet::ptr_t pkt)
{
	if (direct_request_pending_ != ip::tcp::endpoint()) {
		frame_fragment::ptr_t frag(new frame_fragment());
		snoop_fragment(node, direct_request_pending_, frag);
		if (frag->status() != frame_fragment::status_failed)
			return false;
	}

	return snoop_packet(node, pkt);
}
