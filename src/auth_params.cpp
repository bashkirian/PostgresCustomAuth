#include "auth_params.h"
#include "userver/clients/http/response.hpp"
#include "userver/clients/http/request.hpp"

#include <cctype>

namespace
{
	bool mustBeQuoted(const std::string& name)
	{
        // icompare instead of case insensitive comparison?
		return
			icompare(name, "cnonce") == 0 ||
			icompare(name, "domain") == 0 ||
			icompare(name, "nonce") == 0 ||
			icompare(name, "opaque") == 0 ||
			icompare(name, "qop") == 0 ||
			icompare(name, "realm") == 0 ||
			icompare(name, "response") == 0 ||
			icompare(name, "uri") == 0 ||
			icompare(name, "username") == 0;
	}

	void formatParameter(std::string& result, const std::string& name, const std::string& value)
	{
		result += name;
		result += '=';
		if (mustBeQuoted(name))
		{
			result += '"';
			result += value;
			result += '"';
		}
		else
		{
			result += value;
		}
	}
}


const std::string HTTPAuthenticationParams::REALM("realm");
const std::string HTTPAuthenticationParams::WWW_AUTHENTICATE("WWW-Authenticate");
const std::string HTTPAuthenticationParams::PROXY_AUTHENTICATE("Proxy-Authenticate");


HTTPAuthenticationParams::HTTPAuthenticationParams()
{
}


HTTPAuthenticationParams::HTTPAuthenticationParams(const std::string& authInfo)
{
	fromAuthInfo(authInfo);
}


HTTPAuthenticationParams::HTTPAuthenticationParams(const server::http::HttpRequest& request)
{
	fromRequest(request);
}


HTTPAuthenticationParams::HTTPAuthenticationParams(const server::http::HttpResponse& response, const std::string& header)
{
	fromResponse(response, header);
}


HTTPAuthenticationParams::~HTTPAuthenticationParams()
{
}


// HTTPAuthenticationParams& HTTPAuthenticationParams::operator = (const HTTPAuthenticationParams& authParams)
// {
// 	NameValueCollection::operator = (authParams);

// 	return *this;
// }


void HTTPAuthenticationParams::fromAuthInfo(const std::string& authInfo)
{
	parse(authInfo.begin(), authInfo.end());
}

void getCredentials(server::http::HttpRequest& request, std::string scheme, std::string authInfo) {
	scheme.clear();
	authInfo.clear();
	if (request.HasHeader("Authentication"))
	{
		const std::string& auth = request.GetHeader(header);
		std::string::const_iterator it  = auth.begin();
		std::string::const_iterator end = auth.end();
		while (it != end && Poco::Ascii::isSpace(*it)) ++it;
		while (it != end && !Poco::Ascii::isSpace(*it)) scheme += *it++;
		while (it != end && Poco::Ascii::isSpace(*it)) ++it;
		while (it != end) authInfo += *it++;
	}
	else throw NotAuthenticatedException();
}

void HTTPAuthenticationParams::fromRequest(const server::http::HttpRequest& request)
{
	std::string scheme;
	std::string authInfo;

	// get authorization scheme name and all followed information
	getCredentials(scheme, authInfo);
	request.getCredentials(scheme, authInfo);

	if (icompare(scheme, "Digest") != 0)
		throw InvalidArgumentException("Could not parse non-Digest authentication information", scheme);

	fromAuthInfo(authInfo);
}

/// ???
void HTTPAuthenticationParams::fromResponse(const server::http::HttpResponse& response, const std::string& header)
{
	NameValueCollection::ConstIterator it = response.find(header);
	if (it == response.end())
		throw NotAuthenticatedException("HTTP response has no authentication header");

	bool found = false;
	while (!found && it != response.end() && icompare(it->first, header) == 0)
	{
		const std::string& headerValue = it->second;
		if (icompare(headerValue, 0, 7, "Digest ") == 0)
		{
			parse(headerValue.begin() + 7, headerValue.end());
			found = true;
		}
		++it;
	}
	if (!found) throw NotAuthenticatedException("No Digest header found");
}


const std::string& HTTPAuthenticationParams::getRealm() const
{
	return get(REALM);
}


void HTTPAuthenticationParams::setRealm(const std::string& realm)
{
	set(REALM, realm);
}


// std::string HTTPAuthenticationParams::toString() const
// {
// 	std::string result;
// 	if (size() == 1 && find(NTLM) != end())
// 	{
// 		result = get(NTLM);
// 	}
// 	else
// 	{
// 		ConstIterator iter = begin();

// 		if (iter != end())
// 		{
// 			formatParameter(result, iter->first, iter->second);
// 			++iter;
// 		}

// 		for (; iter != end(); ++iter)
// 		{
// 			result.append(", ");
// 			formatParameter(result, iter->first, iter->second);
// 		}
// 	}
// 	return result;
// }


void HTTPAuthenticationParams::parse(std::string::const_iterator first, std::string::const_iterator last)
{
    // ???
	enum State
	{
		STATE_INITIAL = 0x0100, // 256
		STATE_FINAL = 0x0200, // 512

		STATE_SPACE = STATE_INITIAL | 0, // 256
		STATE_TOKEN = 1,
		STATE_EQUALS = 2,
		STATE_VALUE = STATE_FINAL | 3, // 515
		STATE_VALUE_QUOTED = 4,
		STATE_VALUE_ESCAPE = 5,
		STATE_COMMA = STATE_FINAL | 6 // 518
	};

	int state = STATE_SPACE;
	std::string token;
	std::string value;

	for (std::string::const_iterator it = first; it != last; ++it)
	{
		switch (state)
		{
		case STATE_SPACE:
			if (std::isalnum(*it) || *it == '_' || *it == '-')
			{
				token += *it;
				state = STATE_TOKEN;
			}
			else if (std::isspace(*it))
			{
				// Skip
			}
			else throw SyntaxException("Invalid authentication information");
			break;

		case STATE_TOKEN:
			if (*it == '=')
			{
				state = STATE_EQUALS;
			}
			else if (std::isalnum(*it) || *it == '_' || *it == '-')
			{
				token += *it;
			}
			else throw SyntaxException("Invalid authentication information");
			break;

		case STATE_EQUALS:
			if (std::isalnum(*it) || *it == '_')
			{
				value += *it;
				state = STATE_VALUE;
			}
			else if (*it == '"')
			{
				state = STATE_VALUE_QUOTED;
			}
			else throw SyntaxException("Invalid authentication information");
			break;

		case STATE_VALUE_QUOTED:
			if (*it == '\\')
			{
				state = STATE_VALUE_ESCAPE;
			}
			else if (*it == '"')
			{
				add(token, value);
				token.clear();
				value.clear();
				state = STATE_COMMA;
			}
			else
			{
				value += *it;
			}
			break;

		case STATE_VALUE_ESCAPE:
			value += *it;
			state = STATE_VALUE_QUOTED;
			break;

		case STATE_VALUE:
			if (std::isspace(*it))
			{
				add(token, value);
				token.clear();
				value.clear();
				state = STATE_COMMA;
			}
			else if (*it == ',')
			{
				add(token, value);
				token.clear();
				value.clear();
				state = STATE_SPACE;
			}
			else
			{
				value += *it;
			}
			break;

		case STATE_COMMA:
			if (*it == ',')
			{
				state = STATE_SPACE;
			}
			else if (std::isspace(*it))
			{
				// Skip
			}
			else throw SyntaxException("Invalid authentication information");
			break;
		}
	}

	if (state == STATE_VALUE)
		add(token, value);

	if (!(state & STATE_FINAL))
		throw SyntaxException("Invalid authentication information");
}