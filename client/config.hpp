#ifndef CONFIG_HPP
#define CONFIG_HPP

#include "key.hpp"
#include <boost/program_options.hpp>

class client_config
{
public:
	client_config();

	unsigned short listen_port() const { return variables_["port"].as<unsigned short>(); }
	std::string content_store_path() const { return variables_["hunk_store_path"].as<std::string>(); }
	network_key node_id() const { return node_id_; }

private:
	boost::program_options::options_description descriptions_;
	boost::program_options::variables_map variables_;
	network_key node_id_;
};

//extern client_config config;

#endif