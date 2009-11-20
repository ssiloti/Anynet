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

#ifndef HUNK_HPP
#define HUNK_HPP

#include <glog/logging.h>

#include "core.hpp"
#include "key.hpp"
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/smart_ptr.hpp>
#include <cstdio>

#ifdef BOOST_WINDOWS
#include <Windows.h>
#else
#include <sys/types.h>
#endif

using namespace boost::interprocess;

class content_store
{
	// We have to put the mapping in a base class to ensure that it is initialized before the region
	struct mapped_content_base
	{
		mapped_content_base(const std::string& path) : mapping(path.c_str(), read_write) {}
		file_mapping mapping;
	};

public:
#ifdef BOOST_WINDOWS
	typedef LONGLONG file_time_t;
#else
	typedef time_t file_time_t;
#endif

	struct mapped_content : mapped_content_base, public payload_buffer
	{
		friend class content_store;

		mapped_content(const std::string& path, std::size_t size)
			: mapped_content_base(path), region(mapping, read_write, 0, size), deleted(false)
		{}

		mapped_content(const std::string& path, std::size_t size, bool temp)
			: mapped_content_base(temp_path(path, size)), region(mapping, read_write, 0, size), deleted(true)
		{
			std::stringstream ss;
			ss << mapping.get_name() << '-' << std::hex << this;
			std::rename(mapping.get_name(), ss.str().c_str());
		}

		virtual mutable_buffer get() { return buffer(region.get_address(), region.get_size()); }
		virtual const_buffer get() const { return buffer(region.get_address(), region.get_size()); }

		~mapped_content()
		{
			if (deleted) {
				std::stringstream ss;
				ss << mapping.get_name() << '-' << std::hex << this;
				DLOG(INFO) << "deleting content " << ss.str().c_str();
				region.~mapped_region();
				mapping.~file_mapping();
#ifdef BOOST_WINDOWS
				::DeleteFileA(ss.str().c_str());
#else
				::unlink(ss.str().c_str());
#endif
			}
		}
	private:
		mapped_region region;
		bool deleted;

		std::string temp_path(const std::string& path, std::size_t size);
	};

	struct stored_content
	{
		boost::weak_ptr<const mapped_content> content;
		file_time_t last_access;
		file_time_t stored;
		std::size_t size;
	};

private:
	typedef std::map<network_key, stored_content> stored_contents_t;
	typedef stored_contents_t::iterator iterator;

public:
	typedef stored_contents_t::const_iterator const_iterator;
	typedef boost::shared_ptr<mapped_content> mapped_content_ptr;
	typedef boost::shared_ptr<const mapped_content> const_mapped_content_ptr;

	content_store(const std::string& path);
	~content_store();

	void flush();
	file_time_t now();

	const_iterator begin() const { return stored_contents_.begin(); }
	const_iterator end() const { return stored_contents_.end(); }

	const_iterator stat(const network_key& key) const { return stored_contents_.find(key); }

	mapped_content_ptr get_temp(std::size_t size);

	const_mapped_content_ptr get(const network_key& key);
	const_mapped_content_ptr put(const network_key& key, const_buffer content);
	const_mapped_content_ptr put(const network_key& key, mapped_content_ptr content);
	void unlink(const network_key& key);

private:
	std::string content_path(const network_key& key, bool create_dirs=false) const;
	void unlink_storage(iterator content);

	stored_contents_t stored_contents_;
	std::string path_;
};

#endif