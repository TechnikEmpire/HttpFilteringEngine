/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "WindowsInMemoryCertificateStore.hpp"

// This crazyness is required to include the necessary headers to work with the Windows OS
// certificate store. There are name conflicts between those headers and openSSL, of course.
#if BOOST_OS_WINDOWS
	#undef _WINSOCKAPI_
	#define _WINSOCKAPI_
	#define NOCRYPT
	#include <windows.h>
	#include <wincrypt.h>

	#ifdef OPENSSL_SYS_WIN32
		#undef X509_NAME
		#undef X509_EXTENSIONS
		#undef X509_CERT_PAIR
		#undef PKCS7_ISSUER_AND_SERIAL
		#undef OCSP_RESPONSE
	#endif // ifdef OPENSSL_SYS_WIN32
#endif // if BOOST_OS_WINDOWS

#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{
				
				WindowsInMemoryCertificateStore::WindowsInMemoryCertificateStore() :
					BaseInMemoryCertificateStore()
				{
					
				}

				WindowsInMemoryCertificateStore::WindowsInMemoryCertificateStore(
					const std::string& countryCode,
					const std::string& organizationName,
					const std::string& commonName
					) : BaseInMemoryCertificateStore(						
						countryCode, 
						organizationName, 
						commonName
						)
				{
					
				}

				WindowsInMemoryCertificateStore::~WindowsInMemoryCertificateStore()
				{
					
				}

				bool WindowsInMemoryCertificateStore::EstablishOsTrust()
				{
					RevokeOsTrust();

					HCERTSTORE hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");

					bool caAreadyGenerated = (m_thisCa != nullptr);

					if (hSysStore != nullptr && caAreadyGenerated)
					{
						unsigned char *buf = nullptr;

						int encodedBytesLen = i2d_X509(m_thisCa, &buf);

						CertAddEncodedCertificateToStore(hSysStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, encodedBytesLen, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

						CertCloseStore(hSysStore, 0);

						OPENSSL_free(buf);

						return true;
					}
					else
					{
						if (!caAreadyGenerated)
						{
							throw std::runtime_error("In WindowsInMemoryCertificateStore::EstablishOsTrust() - Attempted to install self signed certificate, to find that self signed cert is nullptr!");
						}
						else
						{
							throw std::runtime_error("In WindowsInMemoryCertificateStore::EstablishOsTrust() - Failed to open OS root certificate store.");
						}
						
					}

					return false;
				}

				void WindowsInMemoryCertificateStore::RevokeOsTrust()
				{
					HCERTSTORE hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");

					if (hSysStore != nullptr)
					{
						char pszNameString[256];
						PCCERT_CONTEXT pCert = nullptr;

						bool shouldRemove = false;

						while ((pCert = CertEnumCertificatesInStore(hSysStore, pCert)) != nullptr)
						{
							shouldRemove = false;

							if (CertGetNameString(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, pszNameString, 128))
							{
								std::string certName(pszNameString);

								if (certName.compare(m_caCommonName) == 0)
								{
									shouldRemove = true;
								}
							}

							if (shouldRemove && pCert != nullptr)
							{
								if (!CertDeleteCertificateFromStore(pCert))
								{
									throw std::runtime_error("In WindowsInMemoryCertificateStore::RevokeOsTrust() - Error removing old CA from OS store.");
								}
								else 
								{
									// Has to happen in order to start pulling certs from the start of the store
									// after we've done a delete.
									pCert = nullptr;
								}								
							}
						}

						CertCloseStore(hSysStore, 0);
					}
					else
					{
						throw std::runtime_error("In WindowsInMemoryCertificateStore::RevokeOsTrust() - Failed to open OS root certificate store.");
					}
				}

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */