#ifndef Net_HTTPAuthenticationParams_INCLUDED
#define Net_HTTPAuthenticationParams_INCLUDED

#include "userver/server/http/http_request.hpp"
#include "userver/server/http/http_response.hpp"

using namespace userver;
class HTTPAuthenticationParams
{
public:
	HTTPAuthenticationParams();

	explicit HTTPAuthenticationParams(const std::string& authInfo);

	explicit HTTPAuthenticationParams(const server::http::HttpRequest& request);

	HTTPAuthenticationParams(const server::http::HttpResponse& response, const std::string& header = WWW_AUTHENTICATE);

	virtual ~HTTPAuthenticationParams();

	HTTPAuthenticationParams& operator = (const HTTPAuthenticationParams& authParams);

	void fromAuthInfo(const std::string& authInfo);

	void fromRequest(const server::http::HttpRequest& request);
		/// Extracts authentication information from the request and creates
		/// HTTPAuthenticationParams by parsing it.
		///
		/// Throws a NotAuthenticatedException if no authentication
		/// information is contained in request.
		/// Throws a InvalidArgumentException if authentication scheme is
		/// unknown or invalid.

	void fromResponse(const server::http::HttpResponse& response, const std::string& header = WWW_AUTHENTICATE);
		/// Extracts authentication information from the response and creates
		/// HTTPAuthenticationParams by parsing it.
		///
		/// Throws a NotAuthenticatedException if no authentication
		/// information is contained in response.
		/// Throws a InvalidArgumentException if authentication scheme is
		/// unknown or invalid.

	void setRealm(const std::string& realm);

	const std::string& getRealm() const;

	std::string toString() const;

	static const std::string REALM;
	static const std::string WWW_AUTHENTICATE;
	static const std::string PROXY_AUTHENTICATE;

private:
	void parse(std::string::const_iterator first, std::string::const_iterator last);
};


#endif // Net_HTTPAuthenticationParams_INCLUDED