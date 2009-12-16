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

#include "node.hpp"
#include "hunk.hpp"
#include "config.hpp"
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/date_time/posix_time/conversion.hpp>
#include <boost/config.hpp>
#include <cstdio>

#ifdef BOOST_WINDOWS
// NTFS has an access time resolution of one hour (ugh)
static const boost::posix_time::time_duration flush_threashold = boost::posix_time::hours(1);
#else
// flush file metadata at most every 10 minutes on POSIX systems
static const boost::posix_time::time_duration flush_threashold = boost::posic_time::minutes(10);
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#endif

using namespace boost::filesystem;

std::string mapped_content::temp_path(const std::string& path, std::size_t size)
{
	boost::filesystem::path p(path);
	std::stringstream ss;
	ss << std::hex << this;
	p /= ss.str();
#ifdef BOOST_WINDOWS
	HANDLE file_hnd = ::CreateFileA(p.string().c_str(), FILE_GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	::SetFilePointer(file_hnd, size, NULL, FILE_BEGIN);
	::SetEndOfFile(file_hnd);
	::CloseHandle(file_hnd);
#else
	::truncate(p.string().c_str(), size);
#endif
	return p.string();
}

namespace detail
{

stored_content content_store_base::do_load_content(directory_iterator file, protocol_t pid, local_node& node)
{
	network_key key(file->filename());
	DLOG(INFO) << "loading content " << file->path().string().c_str();
#ifdef BOOST_WINDOWS
	HANDLE file_hnd = ::CreateFileA(file->path().string().c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	FILETIME stored, accessed;
	hunk_descriptor_t hunk_desc = node.load_existing_hunk(pid, key, ::GetFileSize(file_hnd, NULL));
	::GetFileTime(file_hnd, &stored, &accessed, NULL);
	hunk_desc->stored = boost::posix_time::from_ftime<boost::posix_time::ptime>(stored);
	hunk_desc->last_access = boost::posix_time::from_ftime<boost::posix_time::ptime>(accessed);
	::CloseHandle(file_hnd);
#else
	// TODO: POSIX version
#endif
	return stored_content(hunk_desc);
}

void content_store_base::do_flush(stored_content& stored)
{
	boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
	if (now - stored.desc->last_access > flush_threashold) {
		std::string path = content_path(stored.desc->id);
#ifdef BOOST_WINDOWS
		HANDLE file_hnd = ::CreateFileA(path.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		LARGE_INTEGER access_i;
		access_i.QuadPart = (stored.desc->last_access - boost::posix_time::ptime(boost::gregorian::date(1601, boost::gregorian::Jan, 01))).total_microseconds();
		access_i.QuadPart *= 10;
		FILETIME last_access;
		last_access.dwLowDateTime = access_i.LowPart;
		last_access.dwHighDateTime = access_i.HighPart;
		::SetFileTime(file_hnd, NULL, &last_access, NULL);
		::CloseHandle(file_hnd);
#else
		utimbuf file_times;
		file_times.actime = stored.desc->last_access;
		file_times.modtime = stored.desc->stored;
		::utime(path.c_str(), &file_times);
#endif
	}
}

mapped_content::ptr content_store_base::get_temp(std::size_t size)
{
	return mapped_content::ptr(new mapped_content(path_, size, true));
}

const_payload_buffer_ptr content_store_base::do_get(stored_content& stored)
{
	stored.desc->last_access = boost::posix_time::second_clock::universal_time();

	mapped_content::ptr content = stored.content.lock();
	
	if (content)
		return content;
	else {
		std::string path = content_path(stored.desc->id);
/*		std::size_t content_size;
#ifdef BOOST_WINDOWS
		HANDLE file_hnd = ::CreateFileA(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		content_size = ::GetFileSize(file_hnd, NULL);
		::CloseHandle(file_hnd);
#else
		stat content_stat;
		stat(path.c_str(), &content_stat);
		content_size = content_stat.st_size;
#endif */
		content.reset(new mapped_content(path, stored.desc->size));
		stored.content = content;
		return content;
	}
}

mapped_content::const_ptr content_store_base::do_put(stored_content& stored, std::vector<const_buffer> content)
{
	std::string path = content_path(stored.desc->id, true);

	std::size_t content_size = 0;
	for (std::vector<const_buffer>::iterator buf = content.begin(); buf != content.end(); ++buf)
		content_size += buffer_size(*buf);

	{
#ifdef BOOST_WINDOWS
		HANDLE file_hnd = ::CreateFileA(path.c_str(), FILE_GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		::SetFilePointer(file_hnd, content_size, NULL, FILE_BEGIN);
		::SetEndOfFile(file_hnd);
		::CloseHandle(file_hnd);
#else
		::truncate(path.c_str(), buffer_size(content));
#endif
		file_mapping mapping(path.c_str(), read_write);
		mapped_region region(mapping, read_write, 0, content_size);

		boost::uint8_t* put_ptr = (boost::uint8_t*)region.get_address();
		for (std::vector<const_buffer>::iterator buf = content.begin(); buf != content.end(); ++buf) {
			std::memcpy(put_ptr, buffer_cast<const void*>(*buf), buffer_size(*buf));
			put_ptr += buffer_size(*buf);
		}
	}

	mapped_content::ptr new_mapping(new mapped_content(path, content_size));
	stored.content = new_mapping;
	return new_mapping;
}

mapped_content::const_ptr content_store_base::do_put(stored_content& stored, mapped_content::ptr content)
{
	content->deleted = false;

	std::stringstream temp_path;
	temp_path << content->mapping.get_name();
	temp_path << '-' << std::hex << content.get();

	// content *should* be unique at this point, should probably add a check for this...
	content.reset();
	
	std::string path = content_path(stored.desc->id, true);

	std::rename(temp_path.str().c_str(), path.c_str());

	mapped_content::ptr new_mapping(new mapped_content(path, stored.desc->size));
	stored.content = new_mapping;
	return new_mapping;
}

void content_store_base::unlink_storage(stored_content& stored)
{
#ifdef BOOST_WINDOWS
	// On Windows we must check for an active mapping and flag it if one exists
	// because Windows is braindamaged and can't unlink open files
	mapped_content::ptr content = boost::const_pointer_cast<mapped_content>(stored.content.lock());
	if (content) {
		content->deleted = true;
		DLOG(INFO) << "unlinking storage " << content->mapping.get_name();
		// We can't delete the file but we can rename it, append the mapping object's address to the name
		// the mapping's destructor will delete it
		std::stringstream ss;
		ss << content->mapping.get_name() << '-' << std::hex << content.get();
		std::string old_name = content->mapping.get_name();
		std::string new_name = ss.str();
		::MoveFileA(content->mapping.get_name(), ss.str().c_str());
	}
	else {
		DLOG(INFO) << "deleteing content " << content_path(stored.desc->id).c_str();
		::DeleteFileA(content_path(stored.desc->id).c_str());
	}
#else
	::unlink(content_path(content->first).c_str());
#endif
}

std::string content_store_base::content_path(const network_key& key, bool create_dirs) const
{
	std::string key_str = key;
	boost::filesystem::path path(path_);
	path /= key_str.substr(0, 2);
	if (create_dirs)
		boost::filesystem::create_directories(path);
	path /= key_str;
	return path.string();
}

} // namespace detail
