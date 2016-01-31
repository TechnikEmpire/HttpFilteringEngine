/*
* Copyright (c) 2016 Jesse Nicholson.
*
* This file is part of Http Filtering Engine.
*
* Http Filtering Engine is free software: you can redistribute it and/or
* modify it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 3 of the License, or (at
* your option) any later version.
*
* In addition, as a special exception, the copyright holders give
* permission to link the code of portions of this program with the OpenSSL
* library.
*
* You must obey the GNU General Public License in all respects for all of
* the code used other than OpenSSL. If you modify file(s) with this
* exception, you may extend this exception to your version of the file(s),
* but you are not obligated to do so. If you do not wish to do so, delete
* this exception statement from your version. If you delete this exception
* statement from all source files in the program, then also delete it
* here.
*
* Http Filtering Engine is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
* Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with Http Filtering Engine. If not, see <http://www.gnu.org/licenses/>.
*/

#include "BaseInMemoryCertificateStore.hpp"

#include <random>
#include <limits>
#include <algorithm>
#include <fstream>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{
				const std::string BaseInMemoryCertificateStore::ContextCipherList{ u8"HIGH:!SSLv2!SRP:!PSK" };

				BaseInMemoryCertificateStore::BaseInMemoryCertificateStore() :
					BaseInMemoryCertificateStore(u8"US", u8"HttpFilteringEngine", u8"HttpFilteringEngine")
				{

				}

				BaseInMemoryCertificateStore::BaseInMemoryCertificateStore(
					const std::string& countryCode,
					const std::string& organizationName,
					const std::string& commonName
					) :
					m_caCountryCode(countryCode),
					m_caOrgName(organizationName),
					m_caCommonName(commonName)
				{
					// Generate self signed CA cert.
					m_thisCaKeyPair = GenerateEcKey();
					m_thisCa = GenerateSelfSignedCert(m_thisCaKeyPair, m_caCountryCode, m_caOrgName, m_caCommonName);
				}

				BaseInMemoryCertificateStore::~BaseInMemoryCertificateStore()
				{
					// XXX TODO - What about the temp EC key? Does it simply die as part of the
					// context? Why is there no method to fetch it later? If it doesn't die with
					// the context, then we need to store it separately. :(
					for (const auto& pair : m_hostContexts)
					{
						auto* nativeHandle = pair.second->native_handle();
						auto* contextCert = SSL_CTX_get0_certificate(nativeHandle);
						auto* privkey = SSL_CTX_get0_privatekey(nativeHandle);

						EVP_PKEY_free(privkey);
						X509_free(contextCert);

						delete pair.second;
					}

					m_hostContexts.clear();
				}

				boost::asio::ssl::context* BaseInMemoryCertificateStore::GetServerContext(const std::string& hostname, X509* originalCertificate)
				{
					ScopedLock lock(m_spoofMutex);

					std::string host = hostname;

					std::transform(host.begin(), host.end(), host.begin(), ::tolower);

					const auto& result = m_hostContexts.find(host);

					if (result != m_hostContexts.end())
					{
						return result->second;
					}										

					if (m_thisCa != nullptr && m_thisCaKeyPair != nullptr && originalCertificate != nullptr)
					{
						char countryBuff[1024];
						char orgBuff[1024];
						char cnBuff[1024];

						int countryLen = 0;
						int orgLen = 0;
						int cnLen = 0;

						X509_NAME* certToSpoofName = X509_get_subject_name(originalCertificate);

						if (certToSpoofName == nullptr)
						{
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to load remote certificate X509_NAME data.");
						}

						cnLen = X509_NAME_get_text_by_NID(certToSpoofName, NID_commonName, cnBuff, 1024);
						orgLen = X509_NAME_get_text_by_NID(certToSpoofName, NID_organizationName, orgBuff, 1024);
						countryLen = X509_NAME_get_text_by_NID(certToSpoofName, NID_countryName, countryBuff, 1024);

						if (countryLen < 0)
						{
							countryLen = 0;
						}

						if (orgLen < 0)
						{
							orgLen = 0;
						}

						if (cnLen < 0)
						{
							cnLen = 0;
						}

						std::string countryCode(countryBuff, countryLen);
						std::string organizationName(orgBuff, orgLen);
						std::string commonName(cnBuff, cnLen);

						EVP_PKEY* spoofedCertKeypair = GenerateEcKey();

						if (spoofedCertKeypair == nullptr)
						{
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to generate EC key for spoofed certificate.");
						}

						// We pass nullptr as the issuer keypair, because we don't want it to be signed yet. We
						// still have modifications to make, such as adding SAN's.
						X509* spoofedCert = IssueCertificate(spoofedCertKeypair, nullptr, false, countryCode, organizationName, commonName);

						if (spoofedCert == nullptr)
						{
							EVP_PKEY_free(spoofedCertKeypair);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to generate X509 structure.");
						}

						// We need to get all the SAN, or Subject Alternative Names out of the certificate
						// we are spoofing, and then add them to our own. This is important for things like
						// wildcard domains. If we ignored SAN's, we'd get hard to diagnose issues while
						// in the proxy where some requests that appear to be to the same host are rejected
						// while others are not. 
						int i;
						int sanNamesCount = -1;
						STACK_OF(GENERAL_NAME)* sanNames = nullptr;

						sanNames = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(originalCertificate, NID_subject_alt_name, nullptr, nullptr);

						sanNamesCount = sk_GENERAL_NAME_num(sanNames);

						// We want to keep each SAN stored in a vector without modification, or any appended
						// special strings like "DNS:". We want this so we can use this vector for the sole
						// purpose of iterating over all extracted SAN's and then using them as keys
						// to point to the same final certificate and or context.
						//
						// The SAN string we're going to copy directly into our spoofed certificate is generated
						// along side this vector, but stored entirely in the sanDnsString variable.
						std::vector<std::string> sanDomains;
						std::string sanDnsString;

						for (i = 0; i < sanNamesCount; i++)
						{
							const GENERAL_NAME* currentName = sk_GENERAL_NAME_value(sanNames, i);

							switch (currentName->type)
							{
							case GEN_DNS:
							{
								std::string dnsNameString(reinterpret_cast<char*>(ASN1_STRING_data(currentName->d.dNSName)));

								auto len = ASN1_STRING_length(currentName->d.dNSName);

								if (len == dnsNameString.size())
								{
									std::transform(dnsNameString.begin(), dnsNameString.end(), dnsNameString.begin(), ::tolower);

									if (sanDomains.size() == 0)
									{
										sanDnsString.append("DNS:");
									}
									else
									{
										sanDnsString.append(",DNS:");
									}

									sanDnsString.append(dnsNameString);

									sanDomains.push_back(dnsNameString);
								}
								else
								{
									// Malformed certificate? SAN has embedded null perhaps?
									break;
								}
							}
							break;

							// case GEN_OTHERNAME:
							// case GEN_EMAIL:
							// case GEN_X400:
							// case GEN_DIRNAME:
							// case GEN_EDIPARTY:
							// case GEN_URI:
							// case GEN_IPADD:
							// case GEN_RID:

							default:
								continue;
							}
						} // End of SAN name loop

						if (sanNames != nullptr)
						{
							sk_GENERAL_NAME_pop_free(sanNames, GENERAL_NAME_free);
						}

						if (sanDnsString.size() > 0)
						{
							if (!Addx509Extension(spoofedCert, NID_subject_alt_name, sanDnsString))
							{
								EVP_PKEY_free(spoofedCertKeypair);
								X509_free(spoofedCert);
								throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to set SAN's for spoofed certificate.");
							}
						}

						// Now we're done altering the cert, so sign it.
						if (m_thisCaKeyPair == nullptr || X509_sign(spoofedCert, m_thisCaKeyPair, EVP_sha256()) == 0)
						{
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to sign certificate.");
						}

						// Now we can create our server context.
						boost::asio::ssl::context* ctx = new boost::asio::ssl::context(boost::asio::ssl::context::tlsv12_server);

						if (ctx == nullptr)
						{
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to allocate new server context for spoofed certificate.");
						}

						ctx->set_options(
							boost::asio::ssl::context::no_compression |
							boost::asio::ssl::context::default_workarounds |
							boost::asio::ssl::context::no_sslv2 | 
							boost::asio::ssl::context::no_sslv3
							);


						if (SSL_CTX_set_cipher_list(ctx->native_handle(), ContextCipherList.c_str()) != 1)
						{
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to set context cipher list.");
						}						

						if (SSL_CTX_use_certificate(ctx->native_handle(), spoofedCert) != 1)
						{
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to set server context certificate.");
						}

						if (SSL_CTX_use_PrivateKey(ctx->native_handle(), spoofedCertKeypair) != 1)
						{
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to set server context private key.");
						}

						SSL_CTX_set_options(ctx->native_handle(), SSL_OP_CIPHER_SERVER_PREFERENCE);

						EC_KEY* tmpNegotiationEcKey;

						if (nullptr == (tmpNegotiationEcKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
						{
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to allocate server context temporary negotiation EC key.");
						}

						if (EC_KEY_generate_key(tmpNegotiationEcKey) != 1)
						{
							EC_KEY_free(tmpNegotiationEcKey);
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Failed to generate server context temporary negotiation EC key.");
						}

						SSL_CTX_set_tmp_ecdh(ctx->native_handle(), tmpNegotiationEcKey);

						bool atLeastOneInsert = false;

						if (sanDomains.size() > 0)
						{
							for (const auto& domain : sanDomains)
							{
								if (m_hostContexts.find(domain) == m_hostContexts.end())
								{
									m_hostContexts.insert({ domain, ctx });
									atLeastOneInsert = true;
								}
							}
						}

						if (m_hostContexts.find(host) == m_hostContexts.end())
						{
							m_hostContexts.insert({ host, ctx });
							atLeastOneInsert = true;
						}

						if (!atLeastOneInsert)
						{
							// In this case, either the user has made an error and is duplicating data, or perhaps
							// something more dirty is going on, where we have spoofed a certificate that is lying
							// about its SN and or SAN's.
							EC_KEY_free(tmpNegotiationEcKey);
							EVP_PKEY_free(spoofedCertKeypair);
							X509_free(spoofedCert);
							delete ctx;
							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Context already exists for specified host.");
						}

						return ctx;
					}
					else
					{
						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GetServerContext(std::string, X509*) - Cannot spoof certificate. Either member CA , member CA keypair or certificate to spoof is nullptr.");
					}
				}

				bool BaseInMemoryCertificateStore::WriteCertificateToFile(X509* cert, const std::string& outputFilePath)
				{
					if (cert != nullptr)
					{
						BIO* bio = BIO_new(BIO_s_mem());

						if (bio != nullptr)
						{
							auto ret = PEM_write_bio_X509(bio, cert);

							if (ret != 1)
							{
								BIO_free(bio);
								return false;
							}

							BUF_MEM* mem = nullptr;
							BIO_get_mem_ptr(bio, &mem);

							if (mem == nullptr || mem->data == nullptr || mem->length == 0)
							{
								BIO_free(bio);
								return false;
							}

							std::string pem(mem->data, mem->length);

							std::ofstream outfile(outputFilePath, std::ios::out | std::ios::trunc || std::ios::binary);

							BIO_free(bio);							

							if (!outfile.fail() && outfile.is_open())
							{
								outfile << pem;
							}

							outfile.close();

							return true;
						}
					}

					return false;
				}

				EVP_PKEY* BaseInMemoryCertificateStore::GenerateEcKey(const int namedCurveId) const
				{
					EC_KEY *eckey = nullptr;

					if ((eckey = EC_KEY_new_by_curve_name(namedCurveId)) == nullptr || EC_KEY_generate_key(eckey) != 1)
					{
						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GenerateEcKey(const int) - Failed to allocate EC_KEY structure.");
					}

					EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

					EVP_PKEY* pkey = nullptr;

					pkey = EVP_PKEY_new();

					if (pkey == nullptr)
					{
						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GenerateEcKey(const int) - Failed to allocate EVP_PKEY structure.");
					}
					else
					{
						if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1)
						{
							EVP_PKEY_free(pkey);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GenerateEcKey(const int) - Failed to assign EC_KEY to EVP_PKEY structure.");
						}
					}

					return pkey;
				}

				X509* BaseInMemoryCertificateStore::GenerateSelfSignedCert(
					EVP_PKEY* issuerKeypair,
					const std::string& countryCode,
					const std::string& organizationName,
					const std::string& commonName
					) const
				{
					X509* selfSigned = IssueCertificate(issuerKeypair, issuerKeypair, true, countryCode, organizationName, commonName);

					if (selfSigned == nullptr)
					{
						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::GenerateSelfSignedCert(EVP_PKEY*, std::string, std::string, std::string) - Failed to allocate X509 structure.");
					}

					return selfSigned;
				}

				X509* BaseInMemoryCertificateStore::IssueCertificate(
					EVP_PKEY* certificateKeypair,
					EVP_PKEY* issuerKeypair,
					const bool isCA,
					const std::string& countryCode,
					const std::string& organizationName,
					const std::string& commonName
					) const
				{
					X509* x509 = X509_new();

					if (!x509)
					{
						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to allocate X509 structure.");
					}

					if (X509_set_version(x509, 2) != 1)
					{
						X509_free(x509);

						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA version number.");
					}

					// Generate random serial number for the cert.
					std::random_device randomDevice;
					std::mt19937 range(randomDevice());
					std::uniform_int_distribution<int> distribution(1, std::numeric_limits<int>::max());

					auto sn = distribution(range);

					// Set serial number.
					if (ASN1_INTEGER_set(X509_get_serialNumber(x509), sn) != 1)
					{
						X509_free(x509);

						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA certificate serial number.");
					}

					// Make cert expire in a year.
					long numberOfDaysValid = 365;
					// Seconds times minutes times hours days.
					long lengthValid = 60 * 60 * 24 * numberOfDaysValid;

					X509_gmtime_adj(X509_get_notBefore(x509), 0);
					X509_gmtime_adj(X509_get_notAfter(x509), lengthValid);

					// Set pub key
					if (X509_set_pubkey(x509, certificateKeypair) != 1)
					{
						X509_free(x509);

						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA public key.");
					}

					X509_NAME* name = X509_get_subject_name(x509);

					if (name != nullptr)
					{
						if (X509_NAME_add_entry_by_txt(name, u8"C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(countryCode.c_str()), -1, -1, 0) == 0)
						{
							//X509_free(x509);

							//throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA certificate country code.");
						}

						if (X509_NAME_add_entry_by_txt(name, u8"O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(organizationName.c_str()), -1, -1, 0) == 0)
						{
							//X509_free(x509);

							//throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA certificate organization.");
						}

						if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0) == 0)
						{
							//X509_free(x509);

							//throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA common name.");
						}
					}
					else
					{
						X509_free(x509);

						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA common name.");
					}

					if (isCA)
					{
						// Following two extensions are standard for CA certs.
						if (!Addx509Extension(x509, NID_basic_constraints, u8"critical,CA:TRUE"))
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA constraints.");
						}

						// Self signed CA, issuer == self.
						if (X509_set_issuer_name(x509, name) != 1)
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA isser name information.");
						}

						if (!Addx509Extension(x509, NID_key_usage, u8"critical,keyCertSign,cRLSign"))
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA key usage.");
						}
					}
					else
					{
						if (m_thisCa == nullptr)
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Cannot issue certificate, as the member CA is nullptr.");
						}

						X509_NAME * issuerName = X509_get_subject_name(m_thisCa);

						if (issuerName == nullptr)
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to get X509_NAME structure from member CA.");
						}

						if (X509_set_issuer_name(x509, issuerName) != 1)
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set issuer name for non CA certificate.");
						}
					}

					// By supplying "hash" as the value for the Subject Key Identifier, apparently,
					// openSSL will properly generate this field itself. From openSSL:
					// 
					// "This is really a string extension and can take two possible values. Either
					// the word hash which will automatically follow the guidelines in RFC3280 or a
					// hex string giving the extension value to include. The use of the hex string
					// is strongly discouraged."
					//
					// More about this extension here:
					// https://www.mankier.com/3/X509V3_get_d2i.3ssl#Supported_Extensions-Pkix_Certificate_Extensions
					// and here:
					// http://security.stackexchange.com/questions/27797/what-damage-could-be-done-if-a-malicious-certificate-had-an-identical-subject-k
					if (!Addx509Extension(x509, NID_subject_key_identifier, u8"hash"))
					{
						X509_free(x509);

						throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string)  - Failed to set self signed CA subject key identifier.");
					}

					if (issuerKeypair != nullptr)
					{
						if (X509_sign(x509, issuerKeypair, EVP_sha256()) == 0)
						{
							X509_free(x509);

							throw std::runtime_error(u8"In BaseInMemoryCertificateStore::IssueCertificate(EVP_PKEY*, EVP_PKEY*, const bool, std::string, std::string, std::string) - Failed to sign certificate.");
						}
					}

					return x509;
				}

				bool BaseInMemoryCertificateStore::Addx509Extension(X509* cert, int nid, std::string strValue) const
				{
					X509_EXTENSION* ex = nullptr;
					X509V3_CTX ctx;

					X509V3_set_ctx_nodb(&ctx);

					X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

					// Because I don't feel right about const_cast'ing on ::c_str(). Not sure
					// why this method doesn't take const char*, so to be totally safe.
					char * arr = new char[strValue.size() + 1];
					std::copy(strValue.begin(), strValue.end(), arr);
					arr[strValue.size()] = '\0';
					ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, arr);

					if (!ex)
					{
						delete[] arr;
						return false;
					}

					X509_add_ext(cert, ex, -1);
					X509_EXTENSION_free(ex);
					delete[] arr;
					return true;
				}

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */
