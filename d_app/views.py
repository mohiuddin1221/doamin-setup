from django.shortcuts import render  # For template rendering (optional)
import ssl
import socket
from datetime import datetime
from rest_framework import status, response, views, permissions
import dns.resolver

class CheckDomainRecordAPIView(views.APIView):
    # permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        domain = request.query_params.get('domain') 
        #domain = "redshopp.tech" 
        print(f"Received domain: {domain}")

        # Validate domain parameter
        if not domain:
            return response.Response({
                "error": "No domain parameter provided."
            }, status=status.HTTP_400_BAD_REQUEST)

        def check_a_record(domain):
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                a_record_list = [str(rdata) for rdata in a_records]
                return "15.197.172.233" in a_record_list
            except dns.resolver.NoAnswer:
                return False
            except dns.resolver.NXDOMAIN:
                return False
            except Exception as e:
                raise e
            
        def check_cname_record(domain):
            try:
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                cname_record_list = [str(rdata.target) for rdata in cname_records]
                print(f"CNAME records for {domain}: {cname_record_list}")
                return True if cname_record_list else False
            except dns.resolver.NoAnswer:
                print(f"No CNAME records found for {domain}")
                return False
            except dns.resolver.NXDOMAIN:
                print(f"NXDOMAIN for {domain}")
                return False
            except Exception as e:
                print(f"Error checking CNAME records for {domain}: {e}")
                raise e

        try:
            # Check A records for both the root domain and www subdomain
            root_domain_confirmed = check_a_record(domain)
            www_domain_confirmed = check_a_record(f"www.{domain}")

            # Check CNAME records for both the root domain and www subdomain
            root_cname_confirmed = check_cname_record(domain)
            www_cname_confirmed = check_cname_record(f"www.{domain}")


            domain_confirmed = (root_domain_confirmed or www_domain_confirmed) and (root_cname_confirmed or www_cname_confirmed)

            return response.Response({
                "domain_confirmed": domain_confirmed,
                "domain": domain,
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return response.Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CheckSSLStatusAPIView(views.APIView):
    # permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        domain = request.query_params.get('domain') 
        print(f"Received domain: {domain}") 

        # Validate domain parameter
        if not domain:
            return response.Response({
                "error": "No domain parameter provided."
            }, status=status.HTTP_400_BAD_REQUEST)

        def check_ssl_status(domain):
            context = ssl.create_default_context()
            try:
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # If no exception is raised, SSL is provisioned
                        return True
            except (ssl.SSLError, socket.error):
                return False

        try:
            # Check SSL status for both the root domain and www subdomain
            root_ssl_status = check_ssl_status(domain)
            www_ssl_status = check_ssl_status(f"www.{domain}")

            ssl_status = root_ssl_status or www_ssl_status
            last_checked_time = datetime.now().isoformat()

            return response.Response({
                "ssl_status": ssl_status,
                "domain": domain,
                "last_check_at": last_checked_time
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return response.Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
