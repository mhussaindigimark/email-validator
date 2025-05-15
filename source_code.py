#source_code.py
import re
import dns.resolver
import smtplib
import requests
import threading
import queue
import time

# Constants
CACHE_TTL = 600
MAX_RETRIES = 3
RETRY_DELAY = 10  # seconds for more 30sec to 60 
DEFAULT_SENDER_EMAIL = "your_verification_email@example.com"  # Change this!
GLOBAL_MAX_CALLS = 100  # Example: 100 global calls
GLOBAL_PERIOD = 30      # per 60 seconds
DOMAIN_MAX_CALLS = 5
DOMAIN_PERIOD = 30

# Initialize a DNS resolver with caching enabled
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8']
resolver.cache = dns.resolver.Cache()


def is_valid_email(email):
    # Comprehensive regex for email validation
    pattern = r'''
        ^                         # Start of string
        (?!.*[._%+-]{2})          # No consecutive special characters
        [a-zA-Z0-9._%+-]{1,64}    # Local part: allowed characters and length limit
        (?<![._%+-])              # No special characters at the end of local part
        @                         # "@" symbol
        [a-zA-Z0-9.-]+            # Domain part: allowed characters
        (?<![.-])                 # No special characters at the end of domain
        \.[a-zA-Z]{2,}$           # Top-level domain with minimum 2 characters
    '''
    
    # Match the entire email against the pattern
    return re.match(pattern, email, re.VERBOSE) is not None

# mx record validation
# Set the cache TTL (in seconds)

def query_dns(record_type, domain):
    try:
        # Try to resolve the record from cache first
        record_name = domain if record_type == 'MX' else f'{domain}.'
        cache_result = resolver.cache.get((record_name, record_type))
        if cache_result is not None and (dns.resolver.mtime() - cache_result.time) < CACHE_TTL:
            return True

        # Otherwise, perform a fresh DNS query
        resolver.timeout = 2
        resolver.lifetime = 2
        resolver.resolve(record_name, record_type)
        return True
    except dns.resolver.NXDOMAIN:
        # The domain does not exist
        return False
    except dns.resolver.NoAnswer:
        # No record of the requested type was found
        return False
    except dns.resolver.Timeout:
        # The query timed out
        return False
    except:
        # An unexpected error occurred
        return False


def has_valid_mx_record(domain):
    # Define a function to handle each DNS query in a separate thread
    def query_mx(results_queue):
        results_queue.put(query_dns('MX', domain))

    def query_a(results_queue):
        results_queue.put(query_dns('A', domain))

    # Start multiple threads to query the MX and A records simultaneously
    mx_queue = queue.Queue()
    a_queue = queue.Queue()
    mx_thread = threading.Thread(target=query_mx, args=(mx_queue,))
    a_thread = threading.Thread(target=query_a, args=(a_queue,))
    mx_thread.start()
    a_thread.start()

    # Wait for both threads to finish and retrieve the results from the queues
    mx_thread.join()
    a_thread.join()
    mx_result = mx_queue.get()
    a_result = a_queue.get()

    return mx_result or a_result


def verify_email(email, sender_email=''):
    """Verifies email existence with greylisting handling."""
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NoAnswer:
        return False, "No MX records found"

    def check_mx_server(mx_record, email_to_check, sender_email, result_queue):
        """Helper function to check a single MX server."""
        try:
            with smtplib.SMTP(str(mx_record.exchange), timeout=10) as smtp_server:
                for attempt in range(MAX_RETRIES):
                    try:
                        smtp_server.ehlo()
                        smtp_server.mail(sender_email)
                        code, message = smtp_server.rcpt(email_to_check)
                        smtp_server.quit()
                        if code == 250:
                            result_queue.put((True, "Email is likely valid (accepted by server)"))
                            return  # Exit the function on success
                        elif code is not None and 400 <= code < 500:
                            result_queue.put((False, f"Recipient rejected by server: {message}"))
                            return
                        elif code in (421, 450, 451, 452, 455):
                            print(f"Temporary failure (greylisting?) for {email_to_check} on attempt {attempt + 1}.  Code: {code}, Message: {message}. Retrying in {RETRY_DELAY} seconds...")
                            time.sleep(RETRY_DELAY)
                        elif message:
                            print(f"SMTP error for {email_to_check} on attempt {attempt + 1}: {code} - {message}")
                            if attempt < MAX_RETRIES - 1:
                                time.sleep(RETRY_DELAY)
                            else:
                                result_queue.put((False, f"SMTP error: {message}"))
                                return
                        else:
                            print(f"No response from {mx_record.exchange} for {email_to_check} on attempt {attempt + 1}. Retrying...")
                            time.sleep(RETRY_DELAY)
                    except Exception as e:
                        print(f"Error connecting to {mx_record.exchange} for {email_to_check}: {e}")
                        result_queue.put((False, f"Error connecting to server: {e}")) #ensure a tuple is always put
                result_queue.put((False, "Max retries exceeded after temporary failures"))
        except Exception as e:
            print(f"Error connecting to {mx_record.exchange} for {email_to_check}: {e}")
            result_queue.put((False, f"Error in check_mx_server: {e}"))
            
        
            
    result_queue = queue.Queue()
    threads = []
    for mx in mx_records:
        thread = threading.Thread(target=check_mx_server, args=(mx, email, sender_email, result_queue))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if not result_queue.empty():
        return result_queue.get() #return the first result
    else:
        return False, "No MX servers checked"

# temporary domain
def is_disposable(domain):
    blacklists = [
        'https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt',
        'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt'
    ]

    for blacklist_url in blacklists:
        try:
            blacklist = set(requests.get(blacklist_url).text.strip().split('\n'))
            if domain in blacklist:
                return True
        except Exception as e:
            print(f'Error loading blacklist {blacklist_url}: {e}')
    return False
