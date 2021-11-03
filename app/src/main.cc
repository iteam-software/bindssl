// ensure_ssl_binding.cpp : Defines the entry point for the application.
//
#include <map>

#include <bind_ssl.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <CLI/CLI.hpp>

using namespace std;
using namespace spdlog::level;

int main(int argc, char** argv)
{
	CLI::App app{
		"Ensures the given certificate is bound to the given endpoint",
		"Ensure SSL Binding"
	};

	level_enum level{info};
	string endpoint = "0.0.0.0:44300";
	string hash = "e635112919bdf5ca852723559d8a18813ae79ecd";
	// string hash = "e635112919bdf5ca852723559d8a18813ae79ece";
	string appid = "214124cd-d05b-4309-9af9-9caa44b2b74a";
	// string appid = "214124cd-d05b-4309-9af9-9caa44b2b743";

	// enum mapper for loglevel
	map<string, level_enum> maplevel{{"error", err}, {"warning", warn}, {"trace", trace}};

	app.add_option("-e,--endpoint", endpoint, "The endpoint to check");
	app.add_option("-H,--hash", hash, "The certificate hash to check");
	app.add_option("-a,--appid", appid, "The appid to bind");

	app.add_option("-v,--verbosity", level, "Log level")
		->transform(CLI::CheckedTransformer(maplevel, CLI::ignore_case));

	CLI11_PARSE(app, argc, argv);

	spdlog::set_level(level);
	auto console = spdlog::stdout_color_mt("app");

	// The user has provided sufficient arguments, so we can proceed.
	auto [address, address_success] = bindssl::SockAddressFromString(endpoint);
	if (!address_success) {
		console->error("Endpoint is invalid");
		return 1;
	}

	auto [query, query_success] = bindssl::MakeQuery(address);
	if (!query_success) {
		console->error("Unable to query http system for SSL status");
		return 1;
	}

	auto [size, size_success] = bindssl::GetQueryBindingSize(query);
	if (!size_success) {
		console->error("Unable to query http system for SSL status");
	}

	auto [binding, binding_success] = bindssl::GetBinding(endpoint, query, size);
	if (!binding_success) {
		console->info("Binding is unhealthy, attempting to rebind");
		auto [bindingset, bindingset_success] = bindssl::MakeNewBindingSet(
				endpoint, hash, appid);
		if (bindingset_success) {
			auto [rebind, rebind_success] = bindssl::SetBinding(endpoint, bindingset);
			if (!rebind_success) {
				console->error("Unable to rebind");
				return -1;
			}
		} else {
			console->error("Unable to rebind");
			return -1;
		}
	}

	console->info("Binding is healthy");
	return 0;
}
